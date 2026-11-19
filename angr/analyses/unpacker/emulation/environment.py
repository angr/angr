from __future__ import annotations

import bisect
import collections
import contextlib
import json
import logging
import ntpath
import os
import re
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import angr_data
import cle
import pefile

from angr import sim_options as o
from angr.errors import (
    AngrError,
    SimError,
    SimIRSBNoDecodeError,
    SimMemoryError,
    SimSegfaultException,
    SimZeroDivisionException,
)
from angr.procedures.definitions import SIM_LIBRARIES, load_win32api_definitions
from angr.state_plugins.unicorn_engine import STOP

from .apis import API_HANDLERS, STATUS_NOT_IMPLEMENTED, ApiHandler
from .exceptions import (
    EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT,
    EXCEPTION_ILLEGAL_INSTRUCTION,
    EXCEPTION_INT_DIVIDE_BY_ZERO,
    EXCEPTION_PRIV_INSTRUCTION,
    ExceptionDispatcher,
)
from .modules import SLOT_SIZE, FakeModule
from .stops import EmulationStop, StopReason
from .syscalls import WIN7_X64_SYSCALLS
from .threads import Thread

if TYPE_CHECKING:
    from angr.project import Project
    from angr.sim_state import SimState

_l = logging.getLogger(__name__)

PAGE = 0x1000
_LAZY_THRESHOLD = 0x100000
_LAZY_CHUNK = 0x10000
_UNMAPPED_RE = re.compile(r"(0x[0-9a-fA-F]+) is not mapped")
_NTDLL_PREFIXES = ("Nt", "Zw", "Rtl", "Ldr", "Dbg", "Ki", "Csr", "Etw")
_CDECL_MODULE_PREFIXES = ("msvcr", "msvcp", "ucrtbase", "vcruntime", "crtdll", "api-ms-win-crt")
_PRELOADED = ("ntdll.dll", "kernel32.dll", "kernelbase.dll")


class AddressSpace:
    """
    Tracks reserved address ranges and hands out free ones.
    """

    def __init__(self, limit: int):
        self._limit = limit
        self._starts: list[int] = []
        self._ranges: list[tuple[int, int]] = []

    def is_free(self, start: int, size: int) -> bool:
        if start < 0x10000 or start + size > self._limit:
            return False
        idx = bisect.bisect_right(self._starts, start)
        if idx and self._ranges[idx - 1][1] > start:
            return False
        return not (idx < len(self._ranges) and self._ranges[idx][0] < start + size)

    def mark(self, start: int, size: int) -> None:
        idx = bisect.bisect_right(self._starts, start)
        self._starts.insert(idx, start)
        self._ranges.insert(idx, (start, start + size))

    def reserve(self, size: int, hint: int, align: int = 0x10000) -> int:
        size = (size + PAGE - 1) & ~(PAGE - 1)
        addr = (hint + align - 1) & ~(align - 1)
        while not self.is_free(addr, size):
            idx = bisect.bisect_right(self._starts, addr)
            nxt = self._ranges[idx - 1][1] if idx and self._ranges[idx - 1][1] > addr else self._ranges[idx][1]
            addr = (nxt + align - 1) & ~(align - 1)
            if addr + size > self._limit:
                raise MemoryError("Emulated address space exhausted")
        self.mark(addr, size)
        return addr

    def find(self, addr: int) -> tuple[int, int] | None:
        idx = bisect.bisect_right(self._starts, addr)
        if idx and self._ranges[idx - 1][1] > addr:
            return self._ranges[idx - 1]
        return None


@dataclass
class _Layout:
    teb_self: int
    teb_stack_base: int
    teb_stack_limit: int
    teb_pid: int
    teb_tid: int
    teb_tls: int
    teb_peb: int
    teb_last_error: int
    peb_image_base: int
    peb_ldr: int
    peb_params: int
    peb_heap: int
    peb_nt_global_flag: int
    peb_os_major: int
    ldr_lists: tuple[int, int, int]
    entry_base: int
    entry_ep: int
    entry_size: int
    entry_full_name: int
    entry_base_name: int
    params_image_path: int
    params_cmdline: int


_LAYOUT32 = _Layout(0x18, 0x04, 0x08, 0x20, 0x24, 0x2C, 0x30, 0x34, 0x08, 0x0C, 0x10, 0x18, 0x68, 0xA4,
                    (0x0C, 0x14, 0x1C), 0x18, 0x1C, 0x20, 0x24, 0x2C, 0x38, 0x40)  # fmt: skip
_LAYOUT64 = _Layout(0x30, 0x08, 0x10, 0x40, 0x48, 0x58, 0x60, 0x68, 0x10, 0x18, 0x20, 0x30, 0xBC, 0x118,
                    (0x10, 0x20, 0x30), 0x30, 0x38, 0x40, 0x48, 0x58, 0x60, 0x70)  # fmt: skip


class WindowsEmulator:
    """
    Concrete user-mode emulation of a PE inside a synthetic Windows process, on top of angr's Unicorn engine.

    DLLs are synthetic images whose exports are trap slots; every API call is dispatched to a Python handler.
    """

    PID = 0x1234
    TID = 0x1238
    STACK_SIZE = 0x100000

    def __init__(self, project: Project, image_path: str | None = None):
        main = project.loader.main_object
        if not isinstance(main, cle.backends.pe.PE):
            raise TypeError("WindowsEmulator only supports PE binaries")
        load_win32api_definitions()
        self.project = project
        self.main = main
        self.is_64bit = project.arch.bits == 64
        self.ptr_size = project.arch.bytes
        self._ptr_fmt = "<Q" if self.is_64bit else "<I"
        self._layout = _LAYOUT64 if self.is_64bit else _LAYOUT32
        self.image_base: int = main.mapped_base
        self.image_size: int = main.max_addr - main.min_addr + 1
        name = ntpath.basename(project.filename or "sample.exe")
        self.image_path = image_path or ("C:\\Users\\admin\\Desktop\\" + (name if "." in name else "sample.exe"))
        with open(main.binary, "rb") as f:
            self.image_file: bytes = f.read()
        self.pe = pefile.PE(data=self.image_file, fast_load=True)
        self.pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            ]
        )

        self.space = AddressSpace(1 << 47 if self.is_64bit else 0x7FFF0000)
        for obj in project.loader.all_objects:
            start = obj.min_addr & ~0xFFFF
            self.space.mark(start, ((obj.max_addr + 0x10000) & ~0xFFFF) - start)

        self.modules: dict[str, FakeModule] = {}
        self.module_order: list[FakeModule] = []
        self.api_slots: dict[int, tuple[FakeModule, str]] = {}
        self.api_counts: collections.Counter[str] = collections.Counter()
        self.api_trace: collections.deque[tuple[str, int, tuple[int, ...]]] = collections.deque(maxlen=4096)
        self.unhandled_apis: collections.Counter[str] = collections.Counter()
        self.messages: list[str] = []
        self.allocations: dict[int, int] = {}
        self.handles: dict[int, object] = {}
        self.threads: list[Thread] = []
        self.current_thread = 0
        self._api_frame = (0, 0)
        self.exit_code: int | None = None
        self.blocks = 0
        self.tick = 0x493E0
        self._next_handle = 0x100
        self._stop_points: set[int] = set()
        self._continuations: dict[int, Callable[[int], None]] = {}
        self._saved_sp: dict[int, int] = {}
        self._watched: list[tuple[int, int]] = []
        self._lazy: dict[int, tuple[int, int]] = {}
        self._committed: set[int] = set()
        self._stop: EmulationStop | None = None
        self._nargs_cache: dict[tuple[str, str], int | None] = {}
        self._next_dll_base = 0x7FF800000000 if self.is_64bit else 0x70000000
        self._next_alloc = 0x20000000 if not self.is_64bit else 0x200000000
        self._ldr_entries: dict[str, int] = {}
        self._export_db_dir = os.environ.get("ANGR_UNPACKER_EXPORTS") or angr_data.get_path("unpacker", "win_exports")
        self._export_db: dict[str, dict[str, int | None]] = {}

        self.state: SimState = self._create_state()
        self.exceptions = ExceptionDispatcher(self)
        self._setup_process()

    #
    # Guest memory helpers
    #

    def read(self, addr: int, size: int) -> bytes:
        """
        Read guest memory. Unmapped or unwritten bytes read as zero.
        """
        if size <= 0:
            return b""
        memory = self.state.memory
        out = bytearray(size)
        pos = 0
        while pos < size:
            chunk = min(size - pos, PAGE - ((addr + pos) & (PAGE - 1)))
            data = memory.concrete_load(addr + pos, chunk, priv=True)
            if len(data) == chunk:
                out[pos : pos + chunk] = data
            elif self._is_mapped(addr + pos):
                # partially symbolic or unwritten page: take the slow path
                bits = memory.load(addr + pos, chunk, priv=True)
                out[pos : pos + chunk] = self.state.solver.eval(bits, cast_to=bytes)
            pos += chunk
        return bytes(out)

    def write(self, addr: int, data: bytes) -> None:
        if data:
            if self._lazy:
                self._commit(addr, len(data))
            self.state.memory.store(addr, data, priv=True)

    def _commit(self, addr: int, size: int) -> bool:
        """
        Back the lazily-allocated chunks overlapping [addr, addr + size) with zeroed memory.
        """
        region = self.space.find(addr)
        if region is None or region[0] not in self._lazy:
            return False
        perms, _ = self._lazy[region[0]]
        committed = False
        for chunk in range(addr & ~(_LAZY_CHUNK - 1), min(addr + size, region[1]), _LAZY_CHUNK):
            if chunk not in self._committed:
                self._committed.add(chunk)
                self.map(chunk, min(_LAZY_CHUNK, region[1] - chunk), perms)
                committed = True
        return committed

    def read_ptr(self, addr: int) -> int:
        return struct.unpack(self._ptr_fmt, self.read(addr, self.ptr_size))[0]

    def write_ptr(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack(self._ptr_fmt, value & ((1 << (8 * self.ptr_size)) - 1)))

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def write_u32(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def read_cstr(self, addr: int, limit: int = 2048) -> str:
        out = bytearray()
        while addr and len(out) < limit:
            chunk = self.read(addr + len(out), 64)
            end = chunk.find(b"\0")
            if end >= 0:
                out += chunk[:end]
                break
            out += chunk
        return out.decode("latin-1")

    def read_wstr(self, addr: int, limit: int = 2048) -> str:
        out = bytearray()
        while addr and len(out) < 2 * limit:
            chunk = self.read(addr + len(out), 64)
            end = next((i for i in range(0, 64, 2) if chunk[i : i + 2] == b"\0\0"), -1)
            if end >= 0:
                out += chunk[:end]
                break
            out += chunk
        return out.decode("utf-16-le", "replace")

    def map(self, addr: int, size: int, perms: int = 3) -> None:
        # unwritten bytes would be symbolic, which the native Unicorn bridge cannot run at speed
        self.state.memory.map_region(addr, size, perms)
        self.state.memory.store(addr, bytes(size), priv=True)

    def _is_mapped(self, addr: int) -> bool:
        try:
            self.state.memory.permissions(addr, priv=True)
        except SimMemoryError:
            return False
        return True

    def _zero_fill_image(self) -> None:
        """
        Map every page of the image and give every byte that has no file backing a concrete zero.
        """
        cursor = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        for section in sorted(self.pe.sections, key=lambda s: s.VirtualAddress):
            chars = section.Characteristics
            perms = (
                (1 if chars & 0x40000000 else 0) | (2 if chars & 0x80000000 else 0) | (4 if chars & 0x20000000 else 0)
            )
            end = (section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData) + PAGE - 1) & ~(
                PAGE - 1
            )
            for page in range(self.image_base + (section.VirtualAddress & ~(PAGE - 1)), self.image_base + end, PAGE):
                if not self._is_mapped(page):
                    self.state.memory.map_region(page, PAGE, perms | 1)
            if section.VirtualAddress > cursor:
                gap_start = self.image_base + cursor
                if self._is_mapped(gap_start):
                    self.write(gap_start, bytes(min(section.VirtualAddress - cursor, PAGE - (cursor & (PAGE - 1)))))
            backed = min(section.SizeOfRawData, section.Misc_VirtualSize or section.SizeOfRawData)
            cursor = section.VirtualAddress + backed
            if end > cursor:
                self.write(self.image_base + cursor, bytes(end - cursor))
            cursor = end

    def alloc(self, size: int, perms: int = 3, hint: int | None = None) -> int:
        size = max((size + PAGE - 1) & ~(PAGE - 1), PAGE)
        addr = self.space.reserve(size, self._next_alloc if hint is None else hint)
        if hint is None:
            self._next_alloc = addr + size
        perms |= 4  # behave like a process without DEP
        if size >= _LAZY_THRESHOLD:
            # large regions are zero-filled on first touch
            self._lazy[addr] = (perms, size)
        else:
            self.map(addr, size, perms)
        self.allocations[addr] = size
        return addr

    @property
    def lazy_regions(self) -> dict[int, tuple[int, int]]:
        return self._lazy

    def protect(self, addr: int, size: int, perms: int) -> None:
        start = addr & ~(PAGE - 1)
        end = (addr + size + PAGE - 1) & ~(PAGE - 1)
        for page in range(start, end, PAGE):
            page_perms = perms & ~4 if self._is_watched(page) else perms
            self.state.memory.permissions(page, page_perms, priv=True)
        self.state.unicorn.uncache_region(start, end - start)

    def new_handle(self, obj: object = None) -> int:
        self._next_handle += 4
        self.handles[self._next_handle] = obj
        return self._next_handle

    #
    # Process setup
    #

    def _create_state(self) -> SimState:
        state = self.project.factory.blank_state(
            addr=self.project.entry,
            add_options={
                o.UNICORN,
                o.UNICORN_SYM_REGS_SUPPORT,
                o.ZERO_FILL_UNCONSTRAINED_MEMORY,
                o.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                o.ENABLE_NX,
                o.STRICT_PAGE_ACCESS,
            },
            remove_options={o.UNICORN_TRACK_BBL_ADDRS, o.UNICORN_TRACK_STACK_POINTERS, o.LAZY_SOLVES},
        )
        state.unicorn.max_steps = 1_000_000
        state.unicorn.cooldown_nonunicorn_blocks = 0
        state.unicorn.cooldown_symbolic_stop = 0
        state.unicorn.cooldown_unsupported_stop = 0
        state.unicorn.cooldown_stop_point = 0
        return state

    def _setup_process(self) -> None:
        lay = self._layout
        self._zero_fill_image()
        self.peb = self.space.reserve(0x10000, 0x7FFB0000)
        self.map(self.peb, 0x10000)
        self.threads.append(self._create_thread(0, 0, stack_hint=0x30000, teb_hint=0x7FFD0000))
        self._ldr = self.peb + 0x1000
        self._arena = self.alloc(0x40000)
        self._arena_next = self._arena
        # a heap header whose Flags/ForceFlags look like an undebugged process (HEAP_GROWABLE only)
        self.process_heap = self.alloc(PAGE)
        for offset in (0x0C, 0x40, 0x70):
            self.write_u32(self.process_heap + offset, 2)

        kusd = 0x7FFE0000
        if self.space.is_free(kusd, PAGE):
            self.space.mark(kusd, 0x10000)
            self.map(kusd, PAGE, 1)
            self.write(kusd + 0x30, "C:\\Windows".encode("utf-16-le"))
            self.write(kusd + 0x264, struct.pack("<III", 1, 6, 1))
            self.write(kusd + 0x14, struct.pack("<Q", 0x01DB3A0000000000))

        self._sentinels = self.alloc(PAGE, 5)
        self._next_sentinel = self._sentinels

        self.write_ptr(self.peb + lay.peb_image_base, self.image_base)
        self.write_ptr(self.peb + lay.peb_ldr, self._ldr)
        self.write_ptr(self.peb + lay.peb_heap, self.process_heap)
        self.write(self.peb + lay.peb_os_major, struct.pack("<III", 6, 1, 7601))
        params = self._arena_alloc(0x400)
        self.write_ptr(self.peb + lay.peb_params, params)
        self.cmdline = f'"{self.image_path}"'
        self._write_unicode_string(params + lay.params_image_path, self.image_path)
        self._write_unicode_string(params + lay.params_cmdline, self.cmdline)
        self._set_thread_register(self.thread)

        self._add_ldr_entry(ntpath.basename(self.image_path), self.image_path, self.image_base, self.image_size,
                            self.project.entry)  # fmt: skip
        for name in _PRELOADED:
            self.load_module(name)
        self._bind_imports()
        self._setup_tls()

    @property
    def thread(self) -> Thread:
        return self.threads[self.current_thread]

    @property
    def teb(self) -> int:
        return self.thread.teb

    @property
    def tls_slots(self) -> list[int]:
        return self.thread.tls_slots

    def _create_thread(self, start: int, param: int, stack_hint: int = 0x1000000, teb_hint: int = 0x7F000000) -> Thread:
        lay = self._layout
        stack_limit = self.space.reserve(self.STACK_SIZE, stack_hint)
        self.map(stack_limit, self.STACK_SIZE)
        teb = self.space.reserve(0x10000, teb_hint)
        self.map(teb, 0x10000)
        tid = self.TID + 4 * len(self.threads)
        self.write_ptr(teb, (1 << (8 * self.ptr_size)) - 1)
        self.write_ptr(teb + lay.teb_stack_base, stack_limit + self.STACK_SIZE)
        self.write_ptr(teb + lay.teb_stack_limit, stack_limit)
        self.write_ptr(teb + lay.teb_self, teb)
        self.write_ptr(teb + lay.teb_pid, self.PID)
        self.write_ptr(teb + lay.teb_tid, tid)
        self.write_ptr(teb + lay.teb_peb, self.peb)
        self.write_ptr(teb + lay.teb_tls, teb + 0x2000)
        return Thread(tid, teb, stack_limit + self.STACK_SIZE, start, param, started=start == 0)

    def spawn_thread(self, start: int, param: int) -> Thread:
        """
        Register a new thread; it first runs when the current thread yields or its time slice ends.
        """
        thread = self._create_thread(start, param)
        self.threads.append(thread)
        return thread

    def _set_thread_register(self, thread: Thread) -> None:
        if self.is_64bit:
            self.state.regs.gs = thread.teb
        else:
            self.state.regs.fs = thread.teb >> 16

    def switch_thread(self) -> bool:
        """
        Hand the CPU to the next runnable thread. Returns False if there is no other thread.
        """
        count = len(self.threads)
        target = next(
            (
                (self.current_thread + step) % count
                for step in range(1, count)
                if self.threads[(self.current_thread + step) % count].alive
            ),
            None,
        )
        if target is None:
            return False
        size = max(offset + length for offset, length in self.project.arch.registers.values())
        current = self.thread
        if current.alive:
            current.registers = self.state.registers.load(0, size)
        self.current_thread = target
        thread = self.thread
        if thread.started:
            self.state.registers.store(0, thread.registers)
            return True
        thread.started = True
        self._set_thread_register(thread)
        self._set_sp(thread.stack_base - 0x2000)

        def exited(_: int) -> None:
            self.exit_thread()

        self.call_guest(thread.start, (thread.param,), exited)
        return True

    def exit_thread(self) -> None:
        self.thread.alive = False
        if not self.switch_thread():
            self.stop(StopReason.RETURNED, "last thread exited")

    def block_thread(self) -> bool:
        """
        For API handlers that must wait: run another thread and make the current one repeat the call when it is next
        scheduled. Returns False (nothing changed) if no other thread can run.
        """
        slot, sp = self._api_frame
        ret_sp, ret_pc = self.sp, self.pc
        self._set_sp(sp)
        self._set_pc(slot)
        if self.switch_thread():
            return True
        self._set_sp(ret_sp)
        self._set_pc(ret_pc)
        return False

    def yield_thread(self, result: int) -> None:
        """
        For blocking API handlers: finish the call with the given result, then let another thread run.
        """
        self.set_reg("rax" if self.is_64bit else "eax", result)
        self.switch_thread()

    def _arena_alloc(self, size: int) -> int:
        addr = self._arena_next
        self._arena_next += (size + 15) & ~15
        if self._arena_next > self._arena + 0x40000:
            self._arena = self.alloc(0x40000)
            addr = self._arena
            self._arena_next = addr + ((size + 15) & ~15)
        return addr

    def alloc_cstr(self, text: str, wide: bool = False) -> int:
        data = text.encode("utf-16-le") + b"\0\0" if wide else text.encode("latin-1", "replace") + b"\0"
        addr = self._arena_alloc(len(data))
        self.write(addr, data)
        return addr

    def _write_unicode_string(self, addr: int, text: str) -> None:
        data = text.encode("utf-16-le")
        buf = self._arena_alloc(len(data) + 2)
        self.write(buf, data + b"\0\0")
        self.write(addr, struct.pack("<HH", len(data), len(data) + 2))
        self.write_ptr(addr + self.ptr_size, buf)

    def _add_ldr_entry(self, base_name: str, full_name: str, base: int, size: int, entry: int) -> None:
        lay = self._layout
        addr = self._arena_alloc(0x100)
        self.write_ptr(addr + lay.entry_base, base)
        self.write_ptr(addr + lay.entry_ep, entry)
        self.write_ptr(addr + lay.entry_size, size)
        self._write_unicode_string(addr + lay.entry_full_name, full_name)
        self._write_unicode_string(addr + lay.entry_base_name, base_name)
        self._ldr_entries[base_name.lower()] = addr
        self._relink_ldr()

    def _relink_ldr(self) -> None:
        entries = list(self._ldr_entries.values())
        init_order = entries[1:]
        orders = (entries, entries, init_order)
        for idx, head_off in enumerate(self._layout.ldr_lists):
            link_off = 2 * self.ptr_size * idx
            nodes = [self._ldr + head_off] + [e + link_off for e in orders[idx]]
            for pos, node in enumerate(nodes):
                self.write_ptr(node, nodes[(pos + 1) % len(nodes)])
                self.write_ptr(node + self.ptr_size, nodes[pos - 1])

    @staticmethod
    def normalize_module_name(name: str) -> str:
        name = ntpath.basename(name.strip().strip('"')).lower()
        if not name:
            return name
        if "." not in name:
            name += ".dll"
        if name.startswith(("api-ms-win-crt", "ext-ms-win-crt")):
            return "ucrtbase.dll"
        if name.startswith(("api-ms-", "ext-ms-")):
            return "kernel32.dll"
        return name

    def _known_exports(self, name: str) -> dict[str, int | None]:
        """
        Export names of a real DLL mapped to their stdcall argument count (None: cdecl or unknown).
        """
        known = self._export_db.get(name)
        if known is None:
            known = {}
            path = os.path.join(self._export_db_dir, os.path.splitext(name)[0] + ".json")
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    known = json.load(f)
            self._export_db[name] = known
        return known

    def load_module(self, name: str) -> FakeModule:
        name = self.normalize_module_name(name)
        module = self.modules.get(name)
        if module is not None:
            return module
        exports: set[str] = set(self._known_exports(name))
        for lib in SIM_LIBRARIES.get(name, []):
            exports.update(lib.prototypes_json)
            exports.update(lib.prototypes)
        for api_name in API_HANDLERS:
            is_nt = api_name.startswith(_NTDLL_PREFIXES) or api_name[0].islower() or api_name[0] == "_"
            if (name == "ntdll.dll" and is_nt) or (name in ("kernel32.dll", "kernelbase.dll") and not is_nt):
                exports.add(api_name)
        probe = FakeModule(name, 0, sorted(exports), self.is_64bit)
        base = self.space.reserve(probe.size, self._next_dll_base)
        self._next_dll_base = base + probe.size
        module = FakeModule(name, base, sorted(exports), self.is_64bit)
        self.map(base, module.size, 5)
        self.write(base, module.image)
        self.modules[name] = module
        self.module_order.append(module)
        for addr, export in module.slot_names.items():
            self.api_slots[addr] = (module, export)
        self._stop_points.update(module.slot_names)
        self._add_ldr_entry(name, "C:\\Windows\\System32\\" + name, base, module.size, 0)
        return module

    def module_by_base(self, base: int) -> FakeModule | None:
        for module in self.module_order:
            if module.base == base:
                return module
        return None

    def resolve_export(self, module: FakeModule, name: str) -> int | None:
        addr = module.resolve(name)
        if addr is not None and addr not in self.api_slots:
            self.api_slots[addr] = (module, name)
            self._stop_points.add(addr)
        return addr

    def resolve_ordinal(self, module: FakeModule, ordinal: int) -> int | None:
        addr = module.resolve_ordinal(ordinal)
        if addr is not None and addr not in self.api_slots:
            self.api_slots[addr] = (module, module.slot_names[addr])
            self._stop_points.add(addr)
        return addr

    def _bind_imports(self) -> None:
        delta = self.main.mapped_base - self.main.linked_base
        for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            module = self.load_module(entry.dll.decode("latin-1"))
            for imp in entry.imports:
                if imp.name is not None:
                    addr = self.resolve_export(module, imp.name.decode("latin-1"))
                else:
                    addr = self.resolve_ordinal(module, imp.ordinal)
                if addr is not None:
                    self.write_ptr(imp.address + delta, addr)

    def _setup_tls(self) -> None:
        self.tls_callbacks: list[int] = []
        tls = getattr(self.pe, "DIRECTORY_ENTRY_TLS", None)
        slots = self.teb + 0x2000
        if tls is None:
            return
        delta = self.main.mapped_base - self.main.linked_base
        raw_start = tls.struct.StartAddressOfRawData
        raw_end = tls.struct.EndAddressOfRawData
        if raw_end > raw_start:
            size = raw_end - raw_start + tls.struct.SizeOfZeroFill
            block = self.alloc(size)
            self.write(block, self.read(raw_start + delta, raw_end - raw_start))
            self.write_ptr(slots, block)
        if tls.struct.AddressOfIndex:
            self.write_u32(tls.struct.AddressOfIndex + delta, 0)
        ptr = tls.struct.AddressOfCallBacks + delta if tls.struct.AddressOfCallBacks else 0
        while ptr and len(self.tls_callbacks) < 32:
            callback = self.read_ptr(ptr)
            if callback == 0:
                break
            self.tls_callbacks.append(callback)
            ptr += self.ptr_size

    #
    # Control flow
    #

    @property
    def pc(self) -> int:
        return self.state.addr

    @property
    def sp(self) -> int:
        return self.state.solver.eval(self.state.regs.sp)

    def _set_pc(self, addr: int) -> None:
        self.state.regs.ip = addr

    def _set_sp(self, value: int) -> None:
        self.state.regs.sp = value

    def reg(self, name: str) -> int:
        if name in ("eflags", "rflags"):
            return self.state.solver.eval(self.state.regs.flags)
        return self.state.solver.eval(self.state.registers.load(name))

    def set_reg(self, name: str, value: int) -> None:
        if name in ("eflags", "rflags"):
            self.state.regs.flags = value & ((1 << self.project.arch.bits) - 1)
            return
        offset, size = self.project.arch.registers[name]
        self.state.registers.store(offset, value & ((1 << (8 * size)) - 1), size=size)

    def stop(self, reason: StopReason, detail: str = "") -> None:
        self._stop = EmulationStop(reason, self.pc, detail)

    def call_guest(self, addr: int, args: tuple[int, ...], continuation: Callable[[int], None]) -> None:
        """
        Transfer control to guest code at addr; continuation(return_value) runs when it returns.
        """
        sentinel = self._next_sentinel
        self._next_sentinel += SLOT_SIZE
        if self._next_sentinel >= self._sentinels + PAGE:
            self._next_sentinel = self._sentinels
        self._stop_points.add(sentinel)
        self._continuations[sentinel] = continuation
        sp = self.sp
        self._saved_sp[sentinel] = sp
        if self.is_64bit:
            sp = ((sp - 0x40 - 8 * max(len(args), 4)) & ~0xF) - 8
            for idx, name in enumerate(("rcx", "rdx", "r8", "r9")):
                if idx < len(args):
                    self.set_reg(name, args[idx])
            for idx in range(4, len(args)):
                self.write_ptr(sp + 8 + 8 * idx, args[idx])
        else:
            sp -= 4 * len(args) + 4
            for idx, arg in enumerate(args):
                self.write_ptr(sp + 4 + 4 * idx, arg)
        self.write_ptr(sp, sentinel)
        self._set_sp(sp)
        self._set_pc(addr)

    def start(self) -> None:
        """
        Queue the TLS callbacks and the entry point.
        """
        self._set_sp(self.thread.stack_base - 0x2000)
        pending = list(self.tls_callbacks)
        is_dll = self.pe.is_dll()

        def finished(_: int) -> None:
            self.stop(StopReason.RETURNED, "entry point returned")

        def next_step(_: int) -> None:
            if pending:
                self.call_guest(pending.pop(0), (self.image_base, 1, 0), next_step)
                return
            entry = self.project.entry
            if is_dll:
                self.call_guest(entry, (self.image_base, 1, 0), finished)
                return
            self.call_guest(entry, (self.peb,), finished)
            if self.is_64bit:
                self.set_reg("rdx", entry)
                self.set_reg("r8", self.peb)
            else:
                self.set_reg("eax", entry)
                self.set_reg("ebx", self.peb)

        next_step(0)

    def watch_exec(self, start: int, size: int) -> None:
        """
        Make a range non-executable so that the first jump into it stops run() with EXEC_TRAP.
        """
        begin = start & ~(PAGE - 1)
        end = (start + size + PAGE - 1) & ~(PAGE - 1)
        self._watched.append((begin, end))
        for page in range(begin, end, PAGE):
            perms = self.state.solver.eval(self.state.memory.permissions(page, priv=True))
            self.state.memory.permissions(page, perms & ~4, priv=True)
        self.state.unicorn.uncache_region(begin, end - begin)

    def unwatch_exec(self, addr: int) -> tuple[int, int] | None:
        for idx, (begin, end) in enumerate(self._watched):
            if begin <= addr < end:
                del self._watched[idx]
                for page in range(begin, end, PAGE):
                    perms = self.state.solver.eval(self.state.memory.permissions(page, priv=True))
                    self.state.memory.permissions(page, perms | 4, priv=True)
                self.state.unicorn.uncache_region(begin, end - begin)
                return begin, end
        return None

    def _is_watched(self, addr: int) -> bool:
        return any(begin <= addr < end for begin, end in self._watched)

    def api_nargs(self, module: FakeModule, name: str) -> int | None:
        key = (module.name, name)
        if key not in self._nargs_cache:
            nargs = self._known_exports(module.name).get(name)
            for lib in SIM_LIBRARIES.get(module.name, []) if nargs is None else []:
                proto = lib.get_prototype(name)
                if proto is not None:
                    nargs = len(proto.args)
                    break
            self._nargs_cache[key] = nargs
        return self._nargs_cache[key]

    def _dispatch_api(self, addr: int) -> None:
        module, name = self.api_slots[addr]
        handler: ApiHandler | None = API_HANDLERS.get(name)
        nargs = handler.nargs if handler is not None else self.api_nargs(module, name)
        cdecl = (
            handler.cdecl
            if handler is not None
            else module.name.startswith(_CDECL_MODULE_PREFIXES) or (nargs is None and name[:1].islower())
        )
        sp = self.sp
        ret_addr = self.read_ptr(sp)
        count = nargs if nargs is not None else 4
        if self.is_64bit:
            args = [self.reg(r) for r in ("rcx", "rdx", "r8", "r9")][:count]
            args += [self.read_ptr(sp + 0x28 + 8 * i) for i in range(count - 4)]
        else:
            args = [self.read_ptr(sp + 4 + 4 * i) for i in range(count)]
        self.api_counts[name] += 1
        self.api_trace.append((name, ret_addr, tuple(args)))
        self._api_frame = (addr, sp)
        new_sp = sp + self.ptr_size
        if not self.is_64bit and not cdecl:
            new_sp += 4 * (nargs or 0)
        self._set_sp(new_sp)
        self._set_pc(ret_addr)
        if handler is None:
            self.unhandled_apis[f"{module.name}!{name}"] += 1
            if nargs is None and not self.is_64bit and not cdecl:
                _l.warning("Unknown argument count for %s!%s; the stack may be unbalanced", module.name, name)
            result = 0
        else:
            result = handler.func(self, args)
        if result is not None:
            self.set_reg("rax" if self.is_64bit else "eax", result)

    def _wind(self, instructions: int | None) -> None:
        """
        Advance to just before the instruction that faulted in the current block.
        """
        if instructions:
            self.state = self.project.factory.successors(self.state, num_inst=instructions).flat_successors[0]

    def _raise_at_instruction(self, instructions: int | None, code: int, info: tuple[int, ...] = ()) -> None:
        with contextlib.suppress(SimError, AngrError, IndexError):
            self._wind(instructions)
        self.exceptions.dispatch(code, self.state.addr, info)

    def _on_fault(self, ex: SimSegfaultException) -> None:
        if self._commit(ex.addr, PAGE):
            return
        if self.space.find(ex.addr) is not None and ex.reason not in ("unmapped", "non-writable", "non-readable"):
            # executing data: allowed, as in a process without DEP
            perms = self.state.solver.eval(self.state.memory.permissions(ex.addr, priv=True))
            self.protect(ex.addr, PAGE, perms | 4)
            return
        self._raise_at_instruction(
            ex.executed_instruction_count, EXCEPTION_ACCESS_VIOLATION, (int(ex.reason == "non-writable"), ex.addr)
        )

    def _on_signal(self, jumpkind: str, block_addr: int) -> None:
        state = self.state
        state.history.jumpkind = "Ijk_Boring"
        pc = state.addr
        if jumpkind == "Ijk_SigFPE_IntDiv":
            self.exceptions.dispatch(EXCEPTION_INT_DIVIDE_BY_ZERO, pc)
        elif jumpkind == "Ijk_SigTRAP":
            previous = self.read(pc - 1, 1)[0] if pc > block_addr else 0
            if previous == 0xCC:
                self.exceptions.dispatch(EXCEPTION_BREAKPOINT, pc - 1)
            else:
                self.exceptions.dispatch(EXCEPTION_PRIV_INSTRUCTION, pc)
        elif jumpkind in ("Ijk_SigILL", "Ijk_NoDecode"):
            self.exceptions.dispatch(EXCEPTION_ILLEGAL_INSTRUCTION, pc)
        else:
            self.exceptions.dispatch(EXCEPTION_ACCESS_VIOLATION, pc, (0, 0))

    @staticmethod
    def _take_unmapped_fault(state: SimState) -> int | None:
        if state.unicorn.stop_reason not in (STOP.STOP_ERROR, STOP.STOP_SEGFAULT) or not state.unicorn.error:
            return None
        match = _UNMAPPED_RE.search(state.unicorn.error)
        state.unicorn.error = None
        return int(match.group(1), 16) if match is not None else None

    def _dispatch_syscall(self) -> None:
        number = self.reg("rax" if self.is_64bit else "eax") & 0xFFFF
        name = WIN7_X64_SYSCALLS.get(number) if self.is_64bit else None
        handler = API_HANDLERS.get(name) if name is not None else None
        label = name or f"syscall_{number:#x}"
        self.api_counts[label] += 1
        if handler is None or not self.is_64bit:
            self.unhandled_apis[f"syscall!{label}"] += 1
            result: int | None = STATUS_NOT_IMPLEMENTED
        else:
            sp = self.sp
            args = [self.reg(r) for r in ("r10", "rdx", "r8", "r9")][: handler.nargs]
            args += [self.read_ptr(sp + 0x28 + 8 * i) for i in range(handler.nargs - 4)]
            self.api_trace.append((label, self.pc, tuple(args)))
            result = handler.func(self, args)
        if result is not None:
            self.set_reg("rax" if self.is_64bit else "eax", result)

    def run(self, max_blocks: int | None = None, timeout: float | None = None) -> EmulationStop:
        """
        Emulate until a stop condition. EXEC_TRAP stops are resumable after unwatch_exec().
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        block_limit = None if max_blocks is None else self.blocks + max_blocks
        self._stop = None
        while True:
            if self._stop is not None:
                return self._stop
            addr = self.state.addr
            if addr in self.api_slots:
                self._dispatch_api(addr)
                continue
            continuation = self._continuations.pop(addr, None)
            if continuation is not None:
                self._set_sp(self._saved_sp.pop(addr))
                continuation(self.reg("rax" if self.is_64bit else "eax"))
                continue
            if self._watched and self._is_watched(addr):
                return EmulationStop(StopReason.EXEC_TRAP, addr)
            if (block_limit is not None and self.blocks >= block_limit) or (
                deadline is not None and time.monotonic() > deadline
            ):
                return EmulationStop(StopReason.BUDGET, addr)
            try:
                successors = self.project.factory.successors(self.state, extra_stop_points=self._stop_points)
            except SimSegfaultException as ex:
                self._on_fault(ex)
                continue
            except SimZeroDivisionException as ex:
                self._raise_at_instruction(ex.executed_instruction_count, EXCEPTION_INT_DIVIDE_BY_ZERO)
                continue
            except SimIRSBNoDecodeError:
                opcode = self.read(addr, 1)[0]
                privileged = opcode in (
                    0xF4,
                    0xFA,
                    0xFB,
                    0xE4,
                    0xE5,
                    0xE6,
                    0xE7,
                    0xEC,
                    0xED,
                    0xEE,
                    0xEF,
                    0x6C,
                    0x6D,
                    0x6E,
                    0x6F,
                )
                self.exceptions.dispatch(
                    EXCEPTION_PRIV_INSTRUCTION if privileged else EXCEPTION_ILLEGAL_INSTRUCTION, addr
                )
                continue
            except (SimError, AngrError, KeyError) as ex:
                # KeyError: the Unicorn engine tried to re-execute instructions it believes touch symbolic data
                return EmulationStop(StopReason.ERROR, addr, f"{type(ex).__name__}: {ex}")
            if not successors.flat_successors:
                return EmulationStop(StopReason.ERROR, addr, f"no successors ({successors.description})")
            new_state = successors.flat_successors[0]
            self.blocks += new_state.unicorn.steps if successors.sort == "Unicorn" else 1
            fault = self._take_unmapped_fault(new_state) if successors.sort == "Unicorn" else None
            new_state.history.trim()
            self.state = new_state
            if (
                len(self.threads) > 1
                and successors.sort == "Unicorn"
                and new_state.unicorn.stop_reason == STOP.STOP_NORMAL
                and new_state.addr not in self.api_slots
                and new_state.addr not in self._continuations
            ):
                # time slice used up
                self.switch_thread()
                continue
            if new_state.history.jumpkind.startswith("Ijk_Sys"):
                new_state.history.jumpkind = "Ijk_Boring"
                self._dispatch_syscall()
            elif fault is not None:
                self._commit(fault, 1)
            elif new_state.history.jumpkind.startswith("Ijk_Sig") or new_state.history.jumpkind == "Ijk_NoDecode":
                self._on_signal(new_state.history.jumpkind, addr)
