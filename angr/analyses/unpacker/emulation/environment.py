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
from typing import TYPE_CHECKING, NamedTuple

import angr_data
import cle
import pefile

from angr import sim_options as o
from angr.engines.unicorn import SimEngineUnicorn
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

from .apis import (
    API_HANDLERS,
    SLEEP_POLL_APIS,
    STATUS_ACCESS_VIOLATION,
    STATUS_NO_MEMORY,
    STATUS_NOT_IMPLEMENTED,
    ApiHandler,
    MappingObject,
    TimerObject,
    WindowClass,
)
from .com import ComRuntime
from .exceptions import (
    EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT,
    EXCEPTION_ILLEGAL_INSTRUCTION,
    EXCEPTION_INT_DIVIDE_BY_ZERO,
    EXCEPTION_PRIV_INSTRUCTION,
    EXCEPTION_SINGLE_STEP,
    ExceptionDispatcher,
)
from .modules import SLOT_SIZE, FakeModule
from .stops import EmulationStop, StopReason
from .syscalls import WIN7_X64_SYSCALLS, WIN7_X86_SYSCALLS
from .threads import EventObject, Thread

if TYPE_CHECKING:
    from angr.project import Project
    from angr.sim_state import SimState

_l = logging.getLogger(__name__)

PAGE = 0x1000
_LAZY_THRESHOLD = 0x100000
_LAZY_CHUNK = 0x10000
_UNMAPPED_RE = re.compile(r"(0x[0-9a-fA-F]+) is not mapped")
# export lists kept apart from a DLL's own list: ntdll's C runtime (mingw's libntdllcrt)
_EXTRA_EXPORT_LISTS = {"ntdll": ("ntdllcrt",)}
_NTDLL_PREFIXES = ("Nt", "Zw", "Rtl", "Ldr", "Dbg", "Ki", "Csr", "Etw")
_WIN32_LOWERCASE_PREFIXES = ("lstr", "wsprintf", "wvsprintf")
_CDECL_MODULE_PREFIXES = ("msvcr", "msvcp", "ucrtbase", "vcruntime", "crtdll", "api-ms-win-crt")
_PRELOADED = ("ntdll.dll", "kernel32.dll", "kernelbase.dll")
# without an API set table: the sets that combase.dll implements (COM and the Windows Runtime); the C runtime sets
# go to ucrtbase and the others to kernel32
_COMBASE_API_SETS = ("api-ms-win-core-com-", "api-ms-win-core-winrt-")
# what follows the layer number in an API set name (api-ms-win-core-file-l1-2-0)
_API_SET_VERSION_RE = re.compile(r"(-l\d+)-\d+(?:-\d+)?$")
# static imports of Windows 7 system DLLs that pull in other DLLs: loading one maps these too, as the Windows
# loader does (a program importing shell32 has user32 mapped)
_DLL_DEPENDENCIES = {
    "advapi32.dll": ("msvcrt.dll",),
    "comctl32.dll": ("user32.dll", "gdi32.dll", "advapi32.dll", "msvcrt.dll"),
    "comdlg32.dll": ("user32.dll", "gdi32.dll", "shlwapi.dll", "shell32.dll", "comctl32.dll"),
    "gdi32.dll": ("user32.dll",),
    "ole32.dll": ("user32.dll", "gdi32.dll", "advapi32.dll", "rpcrt4.dll", "msvcrt.dll"),
    "oleaut32.dll": ("ole32.dll", "user32.dll", "gdi32.dll"),
    "shell32.dll": ("user32.dll", "gdi32.dll", "shlwapi.dll", "advapi32.dll", "msvcrt.dll"),
    "shlwapi.dll": ("user32.dll", "gdi32.dll", "advapi32.dll", "msvcrt.dll"),
    "user32.dll": ("gdi32.dll",),
    "wininet.dll": ("user32.dll", "shlwapi.dll", "advapi32.dll", "msvcrt.dll"),
    "winmm.dll": ("user32.dll", "advapi32.dll", "msvcrt.dll"),
    "ws2_32.dll": ("rpcrt4.dll", "msvcrt.dll"),
}
_KUSER_SHARED_DATA = 0x7FFE0000
# KUSER_SHARED_DATA.TickCountMultiplier of a 15.625 ms clock: milliseconds = TickCount * multiplier >> 24
_TICK_MULTIPLIER = 0x0FA00000
SYSTEM_TIME_BASE = 0x01DB3A0000000000
# Where 32-bit DLLs and allocations go. Import recovery takes aligned values in the dumped image that are API
# addresses, or point into an allocation, for import cells, so those addresses must not be values that data holds
# anyway: DLLs lie where the address's third byte is 0x80 or more and its top byte is not 0x7F (no text, no UTF-16
# text or 16-bit table read at an odd offset, no float), allocations where the top byte is a control character that
# text does not use.
_X86_DLL_BASE = 0x75A30000
_X86_DLL_WINDOW = 0x00800000
_X86_ALLOC_BASE = 0x13A70000
_HEAP_GRANULARITY = 16
_HEAP_SEGMENT = 0x100000
# the NT heap hands blocks from this size on to VirtualAlloc
_HEAP_LARGE_BLOCK = 0x7F000


class UnlistedExport(NamedTuple):
    """
    An export that was asked of a DLL whose export list does not have it: a gap in the list, or a name that Windows
    does not export either (a probe).
    """

    dll: str
    #: The export's name, or "#<ordinal>"
    name: str
    #: Asked for by the image's import directory (it got a slot anyway) rather than looked up at run time (not found)
    static: bool


class AddressSpaceExhausted(MemoryError):
    """
    No free range of the requested size is left in the emulated address space.
    """


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
                raise AddressSpaceExhausted("Emulated address space exhausted")
        self.mark(addr, size)
        return addr

    @property
    def limit(self) -> int:
        return self._limit

    def next_start(self, addr: int) -> int:
        """
        Where the first region above addr starts (the end of the address space if there is none).
        """
        idx = bisect.bisect_right(self._starts, addr)
        return self._starts[idx] if idx < len(self._starts) else self._limit

    def find(self, addr: int) -> tuple[int, int] | None:
        idx = bisect.bisect_right(self._starts, addr)
        if idx and self._ranges[idx - 1][1] > addr:
            return self._ranges[idx - 1]
        return None


def file_backed_size(section: pefile.SectionStructure) -> int:
    """
    How many bytes of a section the loader takes from the file: the raw data up to the end of the section's last
    page. Raw bytes past VirtualSize stay (Themida 3.x decompresses from them); only what lies past the raw data is zero.
    """
    virtual = section.Misc_VirtualSize or section.SizeOfRawData
    return min(section.SizeOfRawData, (virtual + PAGE - 1) & ~(PAGE - 1))


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
    params_current_directory: int


_LAYOUT32 = _Layout(0x18, 0x04, 0x08, 0x20, 0x24, 0x2C, 0x30, 0x34, 0x08, 0x0C, 0x10, 0x18, 0x68, 0xA4,
                    (0x0C, 0x14, 0x1C), 0x18, 0x1C, 0x20, 0x24, 0x2C, 0x38, 0x40, 0x24)  # fmt: skip
_LAYOUT64 = _Layout(0x30, 0x08, 0x10, 0x40, 0x48, 0x58, 0x60, 0x68, 0x10, 0x18, 0x20, 0x30, 0xBC, 0x118,
                    (0x10, 0x20, 0x30), 0x30, 0x38, 0x40, 0x48, 0x58, 0x60, 0x70, 0x38)  # fmt: skip


class WindowsEmulator:
    """
    Concrete user-mode emulation of a PE inside a synthetic Windows process, on top of angr's Unicorn engine.

    DLLs are synthetic images whose exports are trap slots; every API call is dispatched to a Python handler.
    """

    PID = 0x1234
    TID = 0x1238
    STACK_SIZE = 0x100000
    # On this engine every API call restarts Unicorn (about 6 ms), so a Sleep loop that waits for a thread which
    # sleeps for a minute costs minutes. After SLEEP_POLL_STREAK identical polls in a row, with every other thread
    # asleep, the next poll lasts until the first of them wakes. Engines with cheap API calls turn this off.
    SLEEP_POLL_FAST_FORWARD: bool = True
    # above the round iteration counts of bounded poll loops (10 to 100), which therefore run unchanged
    SLEEP_POLL_STREAK = 128

    # guest time advances with executed work: blocks per millisecond here (Icicle counts instructions), and with
    # clock reads, which are expensive on Unicorn (every API call restarts the engine)
    WORK_PER_MS = 200_000
    CLOCK_READS_PER_MS = 20

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
        self._export_db_dir = os.environ.get("ANGR_UNPACKER_EXPORTS") or angr_data.get_path("unpacker", "win_exports")
        self._export_db: dict[str, dict[str, int | None]] = {}
        self._api_sets = self._load_api_sets()
        self.unlisted_exports: list[UnlistedExport] = []
        # the image loaded, so every name its import directory asks for exists in the named DLL
        self._static_imports: dict[str, set[str]] = {}
        for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("latin-1")
            for imp in entry.imports:
                if imp.name is not None:
                    export = imp.name.decode("latin-1")
                    self._static_imports.setdefault(self._import_host(dll, export), set()).add(export)
        size = max(main.max_addr - main.min_addr + 1, self.pe.OPTIONAL_HEADER.SizeOfImage)
        self.image_size: int = (size + PAGE - 1) & ~(PAGE - 1)

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
        # heap blocks (address -> granted size), free blocks by size, and the segment being carved
        self._heap_blocks: dict[int, int] = {}
        self._heap_free: dict[int, list[int]] = collections.defaultdict(list)
        self._heap_cursor = 0
        self._heap_end = 0
        self.file_views: set[int] = set()
        # as when started from Explorer: the directory of the image
        self.current_directory = ntpath.dirname(self.image_path)
        # environment variables by upper-case name: (name, value)
        self.environment: dict[str, tuple[str, str]] = {}
        for variable, value in (
            ("APPDATA", "C:\\Users\\admin\\AppData\\Roaming"),
            ("ComSpec", "C:\\Windows\\system32\\cmd.exe"),
            ("LOCALAPPDATA", "C:\\Users\\admin\\AppData\\Local"),
            ("NUMBER_OF_PROCESSORS", "4"),
            ("OS", "Windows_NT"),
            ("Path", "C:\\Windows\\system32;C:\\Windows"),
            ("PROCESSOR_ARCHITECTURE", "AMD64" if self.is_64bit else "x86"),
            ("ProgramData", "C:\\ProgramData"),
            ("ProgramFiles", "C:\\Program Files"),
            ("SystemDrive", "C:"),
            ("SystemRoot", "C:\\Windows"),
            ("TEMP", "C:\\Users\\admin\\AppData\\Local\\Temp"),
            ("TMP", "C:\\Users\\admin\\AppData\\Local\\Temp"),
            ("USERNAME", "admin"),
            ("USERPROFILE", "C:\\Users\\admin"),
            ("windir", "C:\\Windows"),
        ):
            self.environment[variable.upper()] = (variable, value)
        # files and directories the program created, by lower-case full path: (path, contents) and path
        self.files: dict[str, tuple[str, bytearray]] = {}
        self.directories: dict[str, str] = {}
        self.named_mappings: dict[str, MappingObject] = {}
        self.handles: dict[int, object] = {}
        self.window_classes: dict[str, WindowClass] = {}
        self.timers: list[TimerObject] = []
        # (predefined key, lower-case path) -> lower-case value name -> (name, type, data)
        self.registry: dict[tuple[int, str], dict[str, tuple[str, int, bytes]]] = {}
        # the path of each key as it was written when the key was created
        self.registry_names: dict[tuple[int, str], str] = {}
        self.threads: list[Thread] = []
        self.current_thread = 0
        self._api_frame = (0, 0)
        self._api_return = 0
        # the Sleep call being repeated, as (thread id, return address, milliseconds), and how often so far
        self._sleep_poll: tuple[int, int, int] | None = None
        self._sleep_polls = 0
        self._syscall_names: dict[int, str] = dict(WIN7_X64_SYSCALLS if self.is_64bit else WIN7_X86_SYSCALLS)
        self.exit_code: int | None = None
        #: Why the Windows loader would not start this image; run() then stops with this error at once.
        self.load_error: str | None = None
        self.blocks = 0
        self.tick = 0x493E0
        self._shared_tick: int | None = None

        self._clock = self.tick
        self._clock_reads = 0
        self._next_handle = 0x100
        self._stop_points: set[int] = set()
        self._continuations: dict[int, Callable[[int], None]] = {}
        self._saved_sp: dict[int, int] = {}
        self._watched: list[tuple[int, int]] = []
        self._rewatch: list[int] = []
        self._lazy: dict[int, tuple[int, int]] = {}
        self._committed: set[int] = set()
        self._stop: EmulationStop | None = None
        self.trap_pending = False
        self._nargs_cache: dict[tuple[str, str], int | None] = {}
        self._next_dll_base = 0x7FF800000000 if self.is_64bit else _X86_DLL_BASE
        self._next_alloc = _X86_ALLOC_BASE if not self.is_64bit else 0x200000000
        self._ldr_entries: dict[str, int] = {}
        self.com = ComRuntime(self)

        self._init_machine()
        self.exceptions = ExceptionDispatcher(self)
        self._setup_process()

    #
    # Guest memory helpers
    #

    def clock_ms(self) -> int:
        """
        Milliseconds since boot: explicit advances (sleeps, time slices) plus time spent executing and reading the
        clock. Polling it in a tight loop returns the same value several times, as on a real machine.
        """
        self._clock_reads += 1
        self._clock = max(
            self._clock, self.tick + self.blocks // self.WORK_PER_MS + self._clock_reads // self.CLOCK_READS_PER_MS
        )
        return self._clock

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
            elif self.is_mapped(addr + pos):
                # partially symbolic or unwritten page: take the slow path
                bits = memory.load(addr + pos, chunk, priv=True)
                out[pos : pos + chunk] = self.state.solver.eval(bits, cast_to=bytes)
            pos += chunk
        return bytes(out)

    def write(self, addr: int, data: bytes) -> None:
        if data:
            if self._lazy:
                self._commit(addr, len(data))
            self._store(addr, data)

    def _store(self, addr: int, data: bytes) -> None:
        # one store per page: the cost of a store that spans many pages grows much faster than its size
        memory = self.state.memory
        pos = 0
        while pos < len(data):
            chunk = PAGE - ((addr + pos) & (PAGE - 1))
            memory.store(addr + pos, data[pos : pos + chunk], priv=True)
            pos += chunk

    def patch(self, addr: int, data: bytes) -> None:
        """
        Write memory that may hold code which has already run.
        """
        self.write(addr, data)
        self.state.unicorn.uncache_region(addr, len(data))

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
        self._store(addr, bytes(size))

    def is_mapped(self, addr: int) -> bool:
        try:
            self.state.memory.permissions(addr, priv=True)
        except SimMemoryError:
            return False
        return True

    def perms(self, addr: int) -> int:
        """
        Permission bits (1 read, 2 write, 4 execute) of the mapped page at addr.
        """
        return self.state.solver.eval(self.state.memory.permissions(addr, priv=True))

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
                if not self.is_mapped(page):
                    self.state.memory.map_region(page, PAGE, perms | 1)
            if section.VirtualAddress > cursor:
                gap_start = self.image_base + cursor
                if self.is_mapped(gap_start):
                    self.write(gap_start, bytes(min(section.VirtualAddress - cursor, PAGE - (cursor & (PAGE - 1)))))
            backed = file_backed_size(section)
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

    def heap_alloc(self, size: int) -> int:
        """
        A zeroed heap block. Small blocks share segments, as on the NT heap (a region per block exhausts the address
        space of programs that make tens of thousands of allocations); large ones get their own region.
        """
        size = max(size, 1)
        granted = (size + _HEAP_GRANULARITY - 1) & ~(_HEAP_GRANULARITY - 1)
        if granted >= _HEAP_LARGE_BLOCK:
            addr = self.alloc(size)
        else:
            free = self._heap_free.get(granted)
            if free:
                addr = free.pop()
                self.write(addr, bytes(granted))
            else:
                # each block follows a header, as a HEAP_ENTRY
                if self._heap_cursor + _HEAP_GRANULARITY + granted > self._heap_end:
                    self._heap_cursor = self.alloc(_HEAP_SEGMENT)
                    self._heap_end = self._heap_cursor + _HEAP_SEGMENT
                addr = self._heap_cursor + _HEAP_GRANULARITY
                self._heap_cursor = addr + granted
            self._heap_blocks[addr] = granted
        self.allocations[addr] = size
        return addr

    def heap_free(self, addr: int) -> None:
        granted = self._heap_blocks.pop(addr, None)
        if granted is not None:
            self._heap_free[granted].append(addr)
            del self.allocations[addr]

    def heap_realloc(self, addr: int, size: int) -> int:
        old_size = self.allocations.get(addr, 0)
        granted = self._heap_blocks.get(addr)
        if granted is not None and max(size, 1) <= granted:
            self.allocations[addr] = max(size, 1)
            return addr
        new = self.heap_alloc(size)
        self.write(new, self.read(addr, min(old_size, size)))
        self.heap_free(addr)
        return new

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

    def add_stop_point(self, addr: int) -> None:
        """
        Make run() look at this address before executing it.
        """
        self._stop_points.add(addr)

    def new_handle(self, obj: object = None) -> int:
        self._next_handle += 4
        self.handles[self._next_handle] = obj
        return self._next_handle

    #
    # Process setup
    #

    def _init_machine(self) -> None:
        self.state: SimState = self._create_state()

    def _create_state(self) -> SimState:
        state = self.project.factory.blank_state(
            addr=self.project.entry,
            add_options={
                o.UNICORN,
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

        kusd = _KUSER_SHARED_DATA
        if self.space.is_free(kusd, PAGE):
            self.space.mark(kusd, 0x10000)
            self.map(kusd, PAGE, 1)
            self.write(kusd + 0x30, "C:\\Windows".encode("utf-16-le"))
            self.write(kusd + 0x264, struct.pack("<III", 1, 6, 1))
            self.write_u32(kusd + 4, _TICK_MULTIPLIER)
            self._shared_tick = -1
            self._sync_shared_time()

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
        # RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath, with a buffer for any path
        self._current_directory_string = params + lay.params_current_directory
        self.write_ptr(self._current_directory_string + self.ptr_size, self._arena_alloc(0x210))
        self.set_current_directory(self.current_directory)
        self._set_thread_register(self.thread)
        # on the thread's own stack from the beginning: handlers and call_guest() are usable before start()
        self._set_sp(self.thread.stack_base - 0x2000)

        self._add_ldr_entry(ntpath.basename(self.image_path), self.image_path, self.image_base, self.image_size,
                            self.project.entry)  # fmt: skip
        for name in _PRELOADED:
            self.load_module(name)
        self._bind_imports()
        self._setup_tls()

    def _sync_shared_time(self) -> None:
        """
        Make the time fields of KUSER_SHARED_DATA, which programs read without any call, follow the clock. Called
        before guest code runs; the page changes only when the clock did.
        """
        if self._shared_tick is None or self._shared_tick == self.tick:
            return
        self._shared_tick = self.tick
        interrupt_time = self.tick * 10000
        tick_count = (self.tick << 24) // _TICK_MULTIPLIER
        # KSYSTEM_TIME: LowPart, High1Time, High2Time
        for offset, value in ((0x08, interrupt_time), (0x14, SYSTEM_TIME_BASE + interrupt_time), (0x320, tick_count)):
            self.write(_KUSER_SHARED_DATA + offset, struct.pack("<QI", value, value >> 32))

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
        Hand the CPU to the next runnable thread. Returns False if the current thread keeps running: there is no
        other thread, or every thread sleeps and the current one wakes first (the clock is moved to that time).
        """
        count = len(self.threads)
        order = [(self.current_thread + step) % count for step in range(1, count)]
        target = next((idx for idx in order if self._runnable(self.threads[idx])), None)
        if target is None and not self._runnable(self.thread):
            # everything is waiting: skip ahead to the next timed wake-up, which may be the current thread's own
            candidates = (*order, self.current_thread)
            sleepers = [idx for idx in candidates if self._wakes_by_time(self.threads[idx])]
            if sleepers:
                earliest = min(sleepers, key=lambda idx: self.threads[idx].wake_tick)
                self.tick = max(self.tick, self.threads[earliest].wake_tick)
                if earliest != self.current_thread:
                    target = earliest
        if target is None:
            return False
        self._sleep_poll = None
        current = self.thread
        if current.alive:
            self._save_registers(current)
        self.current_thread = target
        thread = self.thread
        if thread.started:
            self._load_registers(thread)
            return True
        thread.started = True
        self._set_thread_register(thread)
        self._set_sp(thread.stack_base - 0x2000)

        def exited(_: int) -> None:
            self.exit_thread()

        self.call_guest(thread.start, (thread.param,), exited)
        return True

    def _save_registers(self, thread: Thread) -> None:
        size = max(offset + length for offset, length in self.project.arch.registers.values())
        thread.registers = self.state.registers.load(0, size)

    def _load_registers(self, thread: Thread) -> None:
        self.state.registers.store(0, thread.registers)

    @staticmethod
    def _wakes_by_time(thread: Thread) -> bool:
        """
        Whether the passing of time alone makes the thread runnable: it sleeps, or its wait has a timeout.
        """
        return thread.alive and (thread.wait_handle is None or thread.timed_wait)

    def _runnable(self, thread: Thread) -> bool:
        if not thread.alive:
            return False
        if thread.wait_handle is None:
            return thread.wake_tick <= self.tick
        if thread.timed_wait and thread.wake_tick <= self.tick:
            return True
        obj = self.handles.get(thread.wait_handle)
        if isinstance(obj, EventObject):
            return obj.signaled
        if isinstance(obj, Thread):
            return not obj.alive
        return True

    def sleep_wake_tick(self, milliseconds: int) -> int:
        """
        When the current thread, which calls Sleep, wakes up.
        """
        wake = self.tick + min(max(milliseconds, 1), 60000)
        if not self.SLEEP_POLL_FAST_FORWARD:
            return wake
        poll = (self.thread.tid, self._api_return, milliseconds)
        if poll != self._sleep_poll:
            self._sleep_poll = poll
            self._sleep_polls = 0
        self._sleep_polls += 1
        if self._sleep_polls < self.SLEEP_POLL_STREAK:
            return wake
        others = [thread for thread in self.threads if thread is not self.thread]
        if any(self._runnable(thread) for thread in others):
            return wake
        # nothing the loop polls for can change before another thread wakes
        wakes = [thread.wake_tick for thread in others if self._wakes_by_time(thread)]
        return max(wake, min(wakes)) if wakes else wake

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
        # a heap block: the next block's (never zero) header follows at 8-byte granularity; module finders read the
        # character at a fixed index of each BaseDllName to pick a name of that length
        padded = (len(data) + 2 + 7) & ~7
        buf = self._arena_alloc(padded + 8)
        self.write(buf, (data + b"\0\0").ljust(padded, b"\0") + struct.pack("<HBBI", 4, 1, 0x0F, 0))
        self.write(addr, struct.pack("<HH", len(data), len(data) + 2))
        self.write_ptr(addr + self.ptr_size, buf)

    def set_current_directory(self, path: str) -> None:
        self.current_directory = path
        # the process parameters hold it with a trailing backslash
        data = (path.rstrip("\\") + "\\").encode("utf-16-le")[:0x206]
        addr = self._current_directory_string
        self.write(self.read_ptr(addr + self.ptr_size), data + b"\0\0")
        self.write(addr, struct.pack("<HH", len(data), 0x208))

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

    def _load_api_sets(self) -> dict[str, str]:
        """
        The DLL that hosts each API set, from api_sets.json next to the export list directory. The key is the set's
        name up to its layer number: the rest of the version does not take part in the match.
        """
        path = os.path.join(os.path.dirname(os.path.normpath(self._export_db_dir)), "api_sets.json")
        if not os.path.isfile(path):
            return {}
        with open(path, "rb") as f:
            table: dict[str, str | None] = json.load(f)
        hosts: dict[str, str] = {}
        for name, host in table.items():
            if host is not None:
                hosts.setdefault(_API_SET_VERSION_RE.sub(r"\1", name.lower()), host.lower())
        return hosts

    def normalize_module_name(self, name: str) -> str:
        """
        The name a module is loaded under: lower case, with an extension, and an API set's host for an API set.
        """
        name = ntpath.basename(name.strip().strip('"')).lower()
        if not name:
            return name
        if "." not in name:
            name += ".dll"
        if not name.startswith(("api-ms-", "ext-ms-")):
            return name
        host = self._api_sets.get(_API_SET_VERSION_RE.sub(r"\1", os.path.splitext(name)[0]))
        if host is not None:
            return host
        # no table, or a set it does not place
        if name.startswith(("api-ms-win-crt", "ext-ms-win-crt")):
            return "ucrtbase.dll"
        if name.startswith(_COMBASE_API_SETS):
            return "combase.dll"
        return "kernel32.dll"

    def _import_host(self, dll: str, export: str) -> str:
        """
        The module that a static import of a name from a DLL binds to. A name asked of an API set whose host's list
        lacks it comes from kernel32 if kernel32's list has it (programs got these names from kernel32 before the
        API sets, so the host's list is the likelier one to have the gap).
        """
        host = self.normalize_module_name(dll)
        if host == "kernel32.dll" or not ntpath.basename(dll).lower().startswith(("api-ms-", "ext-ms-")):
            return host
        listed = self._known_exports(host)
        if listed and export not in listed and export in self._known_exports("kernel32.dll"):
            self._note_unlisted(host, export, True)
            return "kernel32.dll"
        return host

    def _known_exports(self, name: str) -> dict[str, int | None]:
        """
        Export names of a real DLL mapped to their stdcall argument count (None: cdecl or unknown).
        """
        known = self._export_db.get(name)
        if known is None:
            known = {}
            stem = os.path.splitext(name)[0]
            for list_name in (stem, *_EXTRA_EXPORT_LISTS.get(stem, ())):
                path = os.path.join(self._export_db_dir, list_name + ".json")
                if os.path.isfile(path):
                    with open(path, "rb") as f:
                        for export, nargs in json.load(f).items():
                            known.setdefault(export, nargs)
            self._export_db[name] = known
        return known

    def has_export_list(self, name: str) -> bool:
        """
        Whether name is a DLL that ships with Windows (one with an export list).
        """
        return bool(self._known_exports(name))

    def _known_ordinals(self, name: str) -> dict[int, str | None]:
        """
        Export ordinals of a real DLL, for those DLLs whose exports are imported by ordinal.
        """
        path = os.path.join(self._export_db_dir, os.path.splitext(name)[0] + ".ordinals.json")
        if not os.path.isfile(path):
            return {}
        with open(path, "rb") as f:
            return {int(ordinal): export for ordinal, export in json.load(f).items()}

    def _known_ordinal_nargs(self, name: str) -> dict[int, int]:
        """
        Stdcall argument counts of a real DLL's exports that have no name, by ordinal.
        """
        path = os.path.join(self._export_db_dir, os.path.splitext(name)[0] + ".ordinal_args.json")
        if not os.path.isfile(path):
            return {}
        with open(path, "rb") as f:
            return {int(ordinal): nargs for ordinal, nargs in json.load(f).items()}

    def load_module(self, name: str) -> FakeModule:
        name = self.normalize_module_name(name)
        module = self.modules.get(name)
        if module is not None:
            return module
        known_exports = self._known_exports(name)
        exports: set[str] = set(known_exports) | self._static_imports.get(name, set())
        for lib in SIM_LIBRARIES.get(name, []):
            exports.update(lib.prototypes_json)
            exports.update(lib.prototypes)
        if not known_exports and name in _PRELOADED:
            # no export list for this DLL: the handlers stand in for one, split by name between ntdll and kernel32
            for api_name in API_HANDLERS:
                is_nt = api_name.startswith(_NTDLL_PREFIXES) or (
                    (api_name[0].islower() or api_name[0] == "_") and not api_name.startswith(_WIN32_LOWERCASE_PREFIXES)
                )
                if is_nt == (name == "ntdll.dll"):
                    exports.add(api_name)
        syscalls: dict[str, int] | None = None
        if name == "ntdll.dll":
            syscalls = {}
            known = {nt_name: number for number, nt_name in self._syscall_names.items()}
            for export in sorted(e for e in exports if e.startswith(("Nt", "Zw")) and e[2:3].isupper()):
                nt_name = "Nt" + export[2:]
                number = known.get(nt_name)
                if number is None:
                    number = known[nt_name] = 0x1000 + len(known)
                syscalls[export] = number
                self._syscall_names[number] = nt_name
        ordinals = self._known_ordinals(name)
        probe = FakeModule(name, 0, sorted(exports), self.is_64bit, ordinals)
        base = self._reserve_module(probe.size)
        stack_bytes: dict[str, int] = {}
        if syscalls and not self.is_64bit:
            known_nargs = self._known_exports(name)
            for export in syscalls:
                handler = API_HANDLERS.get(export)
                nargs = handler.nargs if handler is not None else known_nargs.get(export)
                stack_bytes[export] = 4 * (nargs or 0)
        listed = bool(known_exports)
        module = FakeModule(name, base, sorted(exports), self.is_64bit, ordinals, syscalls, stack_bytes, listed)
        for ordinal, nargs in self._known_ordinal_nargs(name).items():
            if ordinals.get(ordinal, "") is None:
                self._nargs_cache[(name, f"ordinal_{ordinal}")] = nargs
        if listed:
            # Windows would not have loaded the image; a gap in the list is the likelier reason, so they get slots
            for export in sorted(self._static_imports.get(name, set()) - known_exports.keys()):
                self._note_unlisted(name, export, True)
        self.map(base, module.size, 5)
        self.write(base, module.image)
        self.modules[name] = module
        self.module_order.append(module)
        for addr, export in module.slot_names.items():
            self.api_slots[addr] = (module, export)
        self._stop_points.update(module.slot_names)
        self._add_ldr_entry(name, "C:\\Windows\\System32\\" + name, base, module.size, 0)
        for dependency in _DLL_DEPENDENCIES.get(name, ()):
            self.load_module(dependency)
        if name == "ntdll.dll" and not self.is_64bit and self.is_mapped(_KUSER_SHARED_DATA):
            # KUSER_SHARED_DATA.SystemCall / SystemCallReturn, which the 32-bit stubs call through
            for offset, export in ((0x300, "KiFastSystemCall"), (0x304, "KiFastSystemCallRet")):
                target = module.resolve(export)
                if target is not None:
                    self.write_ptr(_KUSER_SHARED_DATA + offset, target)
        return module

    def _reserve_module(self, size: int) -> int:
        hint = self._next_dll_base
        if not self.is_64bit:
            # stay inside the upper half of a 16 MB block (see _X86_DLL_BASE); the last block is the one below 0x7F
            while hint < 0x7E000000 and not (
                hint & _X86_DLL_WINDOW
                and (hint + size - 1) & _X86_DLL_WINDOW
                and (hint + size - 1) >> 24 == hint >> 24
                and self.space.is_free(hint, size)
            ):
                step = hint + 0x10000
                hint = step if step & _X86_DLL_WINDOW else step | _X86_DLL_WINDOW
        base = self.space.reserve(size, hint)
        self._next_dll_base = base + size
        return base

    def is_image(self, base: int) -> bool:
        """
        Whether the region that starts at base is a mapped image (the program or a DLL).
        """
        return base == self.image_base & ~0xFFFF or self.module_by_base(base) is not None

    def module_by_base(self, base: int) -> FakeModule | None:
        for module in self.module_order:
            if module.base == base:
                return module
        return None

    def _note_unlisted(self, dll: str, name: str, static: bool) -> None:
        entry = UnlistedExport(dll, name, static)
        if entry not in self.unlisted_exports:
            self.unlisted_exports.append(entry)
            _l.warning(
                "%s!%s is not in the DLL's export list (%s)",
                dll,
                name,
                "imported statically: given a slot" if static else "looked up at run time: not found",
            )

    def resolve_export(self, module: FakeModule, name: str, required: bool = False) -> int | None:
        """
        The trap address of an export. A DLL that has an export list only has the names in the list; a DLL without
        one has every name it is asked for.

        :param required:    The process cannot run without it (a static import): it gets a slot in any case.
        """
        addr = module.resolve(name, create=required or not module.listed)
        return self._resolved(module, name, addr, module.listed)

    def resolve_ordinal(self, module: FakeModule, ordinal: int, required: bool = False) -> int | None:
        """
        The trap address of an export by ordinal. Only ordinals from the DLL's ordinal list name an export; another
        ordinal is not found if anything is known about the DLL's exports, and gets a slot of its own otherwise
        or if it is required.
        """
        known = module.listed or module.has_ordinals
        addr = module.resolve_ordinal(ordinal, create=required or not known)
        return self._resolved(module, f"#{ordinal}", addr, known)

    def _resolved(self, module: FakeModule, name: str, addr: int | None, known: bool) -> int | None:
        if addr is None:
            self._note_unlisted(module.name, name, False)
        elif addr not in self.api_slots:
            # a spare slot
            if known:
                self._note_unlisted(module.name, name, True)
            self.api_slots[addr] = (module, module.slot_names[addr])
            self._stop_points.add(addr)
        return addr

    def _bind_imports(self) -> None:
        delta = self.main.mapped_base - self.main.linked_base
        for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("latin-1")
            module = self.load_module(dll)
            for imp in entry.imports:
                if imp.name is not None:
                    export = imp.name.decode("latin-1")
                    addr = self.resolve_export(self.load_module(self._import_host(dll, export)), export, required=True)
                else:
                    addr = self.resolve_ordinal(module, imp.ordinal, required=True)
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
        # the loader reads the template and the callback list and writes the index while it initializes the
        # process: a directory that points outside the image makes it fault, and the process never starts
        image_end = self.image_base + self.image_size
        for what, start, size in (
            ("raw data", raw_start, max(raw_end - raw_start, 0)),
            ("index", tls.struct.AddressOfIndex, 4),
            ("callback list", tls.struct.AddressOfCallBacks, self.ptr_size),
        ):
            if size and start and not self.image_base <= start + delta <= start + delta + size <= image_end:
                self.load_error = (
                    f"the TLS directory's {what} ({start + delta:#x}, {size:#x} bytes) is outside the image: "
                    "the Windows loader faults on it and the process does not start"
                )
                return
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

    def call_guest(
        self,
        addr: int,
        args: tuple[int, ...],
        continuation: Callable[[int], None],
        return_address: int | None = None,
    ) -> None:
        """
        Transfer control to guest code at addr; continuation(return_value) runs when it returns.

        :param return_address:  Where the call returns to, if not a fresh sentinel; code that looks at its return
                                address expects some callers inside a system DLL.
        """
        if return_address is None:
            sentinel = self._next_sentinel
            self._next_sentinel += SLOT_SIZE
            if self._next_sentinel >= self._sentinels + PAGE:
                self._next_sentinel = self._sentinels
        else:
            sentinel = return_address
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
            # kernel32!BaseThreadInitThunk calls the entry point; protectors find kernel32 by scanning down from
            # the return address for an MZ header
            thunk = self.resolve_export(self.load_module("kernel32.dll"), "BaseThreadInitThunk", required=True)
            assert thunk is not None
            top = self.sp
            if not self.is_64bit:
                # the stack of a Windows 7 main thread: __RtlUserThreadStart's arguments (entry, PEB) at the top, then
                # BaseThreadInitThunk's frame, which ebp points at; packers read both
                start = self.resolve_export(self.load_module("ntdll.dll"), "RtlUserThreadStart", required=True)
                assert start is not None
                self.write(top - 0xC, struct.pack("<III", entry, self.peb, 0))
                frame = top - 0x6C
                self.write(frame, struct.pack("<III", top - 0x2C, start + SLOT_SIZE - 4, self.peb))
                self._set_sp(frame)
                self.set_reg("ebp", frame)
            self.call_guest(entry, (self.peb,), finished, return_address=thunk + SLOT_SIZE - 4)
            if self.is_64bit:
                self.set_reg("rdx", entry)
                self.set_reg("r8", self.peb)
            else:
                # BaseThreadInitThunk takes the entry in edx, as a fastcall
                self.set_reg("eax", entry)
                self.set_reg("ebx", self.peb)
                self.set_reg("ecx", 0)
                self.set_reg("edx", entry)

        next_step(0)

    def trace_to_api(self, addr: int, max_blocks: int = 20000) -> int | None:
        """
        Run the code at addr on a throw-away copy of the process until it reaches an API. Returns the API's trap
        address, or None if it gets anywhere else. Used to see through import wrappers; the process is not changed.

        A wrapper stands in for the API: it enters it with the stack as it found it (its caller's return address on
        top). Code that reaches an API any other way is not one - for example the middle of a wrapper, or data,
        that a constant in the image happens to point at.
        """
        if self.read(addr, 16) == bytes(16):
            # zeroed data, not code
            return None
        state = self.state.copy()
        state.unicorn.max_steps = max_blocks
        sp = self.sp - 0x400
        state.memory.store(sp, bytes(self.ptr_size), priv=True)
        state.registers.store(self.project.arch.sp_offset, sp, size=self.ptr_size)
        state.registers.store(self.project.arch.ip_offset, addr, size=self.ptr_size)
        for _ in range(16):
            pc = state.addr
            slot = self.api_slots.get(pc)
            if slot is not None:
                reached_sp = state.solver.eval(state.registers.load(self.project.arch.sp_offset, self.ptr_size))
                if slot[1] != "KiFastSystemCall":
                    return pc if reached_sp == sp else None
                if reached_sp != sp - self.ptr_size:
                    return None
                # entered through a copied system-call stub: the number names the API
                number = state.solver.eval(state.registers.load(self.project.arch.registers["eax"][0], 4)) & 0xFFFF
                name = self._syscall_names.get(number)
                return slot[0].resolve(name, create=False) if name is not None else None
            if self.space.find(pc) is None:
                return None
            try:
                successors = self.project.factory.successors(state, extra_stop_points=self._stop_points)
            except (SimError, AngrError, KeyError):
                return None
            finally:
                self._forget_native_failures()
            if not successors.flat_successors:
                return None
            if successors.sort == "Unicorn" and successors.flat_successors[0].unicorn.steps >= max_blocks:
                return None
            state = successors.flat_successors[0]
            if state.history.jumpkind != "Ijk_Boring" and not state.history.jumpkind.startswith(
                ("Ijk_Call", "Ijk_Ret")
            ):
                return None
            state.history.trim()
        return None

    def watch_exec(self, start: int, size: int) -> None:
        """
        Make a range non-executable so that the first jump into it stops run() with EXEC_TRAP.
        """
        begin = start & ~(PAGE - 1)
        end = (start + size + PAGE - 1) & ~(PAGE - 1)
        self._watched.append((begin, end))
        for page in range(begin, end, PAGE):
            perms = self.perms(page)
            self.state.memory.permissions(page, perms & ~4, priv=True)
        self.state.unicorn.uncache_region(begin, end - begin)

    def unwatch_exec(self, addr: int) -> tuple[int, int] | None:
        for idx, (begin, end) in enumerate(self._watched):
            if begin <= addr < end:
                del self._watched[idx]
                for page in range(begin, end, PAGE):
                    perms = self.perms(page)
                    self.state.memory.permissions(page, perms | 4, priv=True)
                self.state.unicorn.uncache_region(begin, end - begin)
                return begin, end
        return None

    def watch_page_after_leaving(self, page: int) -> None:
        """
        Watch a page again at the first API call made from outside it.
        """
        self._rewatch.append(page)

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
        com_slot = self.com.slots.get(addr)
        handler: ApiHandler | None
        if com_slot is not None:
            # a method of a stub COM object
            module_name, name, handler = "com", com_slot.name, com_slot.handler
            nargs: int | None = handler.nargs
            cdecl = False
        else:
            module, name = self.api_slots[addr]
            module_name = module.name
            handler = API_HANDLERS.get(name)
            nargs = handler.nargs if handler is not None else self.api_nargs(module, name)
            cdecl = (
                handler.cdecl
                if handler is not None
                else module_name.startswith(_CDECL_MODULE_PREFIXES) or (nargs is None and name[:1].islower())
            )
        if name not in SLEEP_POLL_APIS:
            self._sleep_poll = None
        sp = self.sp
        ret_addr = self.read_ptr(sp)
        if self._rewatch:
            pending = self._rewatch
            self._rewatch = [page for page in pending if page <= ret_addr < page + PAGE]
            for page in pending:
                if not page <= ret_addr < page + PAGE:
                    self.watch_exec(page, PAGE)
        count = nargs if nargs is not None else 4
        if self.is_64bit:
            args = [self.reg(r) for r in ("rcx", "rdx", "r8", "r9")][:count]
            args += [self.read_ptr(sp + 0x28 + 8 * i) for i in range(count - 4)]
        else:
            args = [self.read_ptr(sp + 4 + 4 * i) for i in range(count)]
        self.api_counts[name] += 1
        self.api_trace.append((name, ret_addr, tuple(args)))
        self._api_frame = (addr, sp)
        self._api_return = ret_addr
        new_sp = sp + self.ptr_size
        if not self.is_64bit and not cdecl:
            new_sp += 4 * (nargs or 0)
        self._set_sp(new_sp)
        self._set_pc(ret_addr)
        if handler is None:
            self.unhandled_apis[f"{module_name}!{name}"] += 1
            if nargs is None and not self.is_64bit and not cdecl:
                _l.warning("Unknown argument count for %s!%s; the stack may be unbalanced", module_name, name)
            result = 0
        else:
            try:
                result = handler.func(self, args)
            except SimSegfaultException:
                # the handler followed a bad pointer argument
                result = STATUS_ACCESS_VIOLATION if name.startswith(("Nt", "Zw")) else 0
            except AddressSpaceExhausted:
                # an allocation that cannot be satisfied fails, as it would on Windows
                result = STATUS_NO_MEMORY if name.startswith(("Nt", "Zw")) else 0
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
        self._forget_native_failures()
        if self._commit(ex.addr, PAGE):
            return
        if self.space.find(ex.addr) is not None and ex.reason not in ("unmapped", "non-writable", "non-readable"):
            # executing data: allowed, as in a process without DEP
            perms = self.perms(ex.addr)
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
            elif previous == 0xF4:
                # hlt: a fault, reported at the instruction
                self.exceptions.dispatch(EXCEPTION_PRIV_INSTRUCTION, pc - 1)
            else:
                self.exceptions.dispatch(EXCEPTION_PRIV_INSTRUCTION, pc)
        elif jumpkind in ("Ijk_SigILL", "Ijk_NoDecode"):
            self.exceptions.dispatch(EXCEPTION_ILLEGAL_INSTRUCTION, pc)
        else:
            self.exceptions.dispatch(EXCEPTION_ACCESS_VIOLATION, pc, (0, 0))

    def _forget_native_failures(self) -> None:
        engine = self.project.factory.default_engine
        if isinstance(engine, SimEngineUnicorn):
            engine._stop_block_addrs_cache.clear()

    @staticmethod
    def _take_unmapped_fault(state: SimState) -> int | None:
        if state.unicorn.stop_reason not in (STOP.STOP_ERROR, STOP.STOP_SEGFAULT) or not state.unicorn.error:
            return None
        match = _UNMAPPED_RE.search(state.unicorn.error)
        state.unicorn.error = None
        return int(match.group(1), 16) if match is not None else None

    def system_call(self, arg_base: int | None = None) -> None:
        """
        Dispatch the system call selected by eax/rax. 32-bit arguments are read from arg_base.
        """
        number = self.reg("rax" if self.is_64bit else "eax") & 0xFFFF
        name = self._syscall_names.get(number)
        handler = API_HANDLERS.get(name) or API_HANDLERS.get("Zw" + name[2:]) if name is not None else None
        label = name or f"syscall_{number:#x}"
        self._sleep_poll = None
        self.api_counts[label] += 1
        if handler is None or (arg_base is None and not self.is_64bit):
            self.unhandled_apis[f"syscall!{label}"] += 1
            result: int | None = STATUS_NOT_IMPLEMENTED
        else:
            if arg_base is None:
                sp = self.sp
                args = [self.reg(r) for r in ("r10", "rdx", "r8", "r9")][: handler.nargs]
                args += [self.read_ptr(sp + 0x28 + 8 * i) for i in range(handler.nargs - 4)]
            else:
                args = [self.read_ptr(arg_base + 4 * i) for i in range(handler.nargs)]
            self.api_trace.append((label, self.pc, tuple(args)))
            try:
                result = handler.func(self, args)
            except SimSegfaultException:
                result = STATUS_ACCESS_VIOLATION
        if result is not None:
            self.set_reg("rax" if self.is_64bit else "eax", result)

    def _on_syscall_instruction(self) -> None:
        if self.is_64bit:
            self.system_call()
            return
        edx = self.reg("edx")
        if self.read(self.pc - 2, 2) == b"\x0f\x34":
            # sysenter: arguments sit above two return addresses; the kernel resumes at KiFastSystemCallRet, a ret
            sp = self.sp
            self._set_pc(self.read_ptr(sp))
            self._set_sp(sp + 4)
            self.system_call(edx + 8)
        else:
            self.system_call(edx)

    def run(self, max_blocks: int | None = None, timeout: float | None = None) -> EmulationStop:
        """
        Emulate until a stop condition. EXEC_TRAP stops are resumable after unwatch_exec().
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        block_limit = None if max_blocks is None else self.blocks + max_blocks
        self._stop = None
        if self.load_error is not None:
            return EmulationStop(StopReason.ERROR, self.pc, self.load_error)
        while True:
            if self._stop is not None:
                return self._stop
            addr = self.state.addr
            if addr in self.api_slots or addr in self.com.slots:
                self._dispatch_api(addr)
                continue
            continuation = self._continuations.pop(addr, None)
            if continuation is not None:
                self._set_sp(self._saved_sp.pop(addr))
                continuation(self.reg("rax" if self.is_64bit else "eax"))
                continue
            if self.trap_pending:
                # a context with the trap flag set was resumed
                self.trap_pending = False
                self._raise_at_instruction(1, EXCEPTION_SINGLE_STEP)
                continue
            if self._watched and self._is_watched(addr):
                return EmulationStop(StopReason.EXEC_TRAP, addr)
            if (block_limit is not None and self.blocks >= block_limit) or (
                deadline is not None and time.monotonic() > deadline
            ):
                return EmulationStop(StopReason.BUDGET, addr)
            self._sync_shared_time()
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
            fault = None
            if successors.sort == "Unicorn":
                fault = self._take_unmapped_fault(new_state)
                if new_state.unicorn.stop_reason in (STOP.STOP_ERROR, STOP.STOP_SEGFAULT):
                    # the engine never retries a block natively once it faulted there; our faults (lazy commits,
                    # execution traps) are transient, so forget them
                    self._forget_native_failures()
            new_state.history.trim()
            self.state = new_state
            if successors.sort == "Unicorn" and new_state.unicorn.trap_flag:
                # the trap flag is set: the engine stopped in front of the instruction that gets single-stepped
                self._raise_at_instruction(1, EXCEPTION_SINGLE_STEP)
                continue
            if (
                len(self.threads) > 1
                and successors.sort == "Unicorn"
                and new_state.unicorn.stop_reason == STOP.STOP_NORMAL
                and new_state.addr not in self.api_slots
                and new_state.addr not in self._continuations
            ):
                # time slice used up
                self.tick += 16
                self.switch_thread()
                continue
            if new_state.history.jumpkind.startswith("Ijk_Sys"):
                new_state.history.jumpkind = "Ijk_Boring"
                self._on_syscall_instruction()
            elif fault is not None:
                self._commit(fault, 1)
            elif new_state.history.jumpkind.startswith("Ijk_Sig") or new_state.history.jumpkind == "Ijk_NoDecode":
                self._on_signal(new_state.history.jumpkind, addr)
