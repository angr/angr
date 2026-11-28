from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

import pypcode

from angr.errors import SimSegfaultException
from angr.rustylib import winemu
from angr.rustylib.winemu import WinVm

from .environment import PAGE, WindowsEmulator, file_backed_size
from .exceptions import (
    EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT,
    EXCEPTION_ILLEGAL_INSTRUCTION,
    EXCEPTION_INT_DIVIDE_BY_ZERO,
    EXCEPTION_PRIV_INSTRUCTION,
    EXCEPTION_SINGLE_STEP,
)
from .stops import EmulationStop, StopReason
from .threads import Thread

if TYPE_CHECKING:
    from angr.project import Project

PROCESSORS_DIR = os.path.join(os.path.dirname(pypcode.__file__), "processors")

_PRIVILEGED_OPCODES = frozenset((0xF4, 0xFA, 0xFB, 0xE4, 0xE5, 0xE6, 0xE7, 0xEC, 0xED, 0xEE, 0xEF, 0x6C, 0x6D, 0x6E,
                                 0x6F))  # fmt: skip


class _StopPoints(set[int]):
    """
    The stop points of the emulator. We add each stop point to the VM as a breakpoint.
    """

    def __init__(self, vm: WinVm):
        super().__init__()
        self._vm = vm

    def add(self, addr: int) -> None:
        if addr not in self:
            super().add(addr)
            self._vm.add_breakpoint(addr)

    def update(self, *others) -> None:
        for other in others:
            for addr in other:
                self.add(addr)

    def discard(self, addr: int) -> None:
        if addr in self:
            super().discard(addr)
            self._vm.remove_breakpoint(addr)


DEFAULT_JIT_THRESHOLD = 32
DEFAULT_THREAD_SLICE = 4_000_000


class IcicleWindowsEmulator(WindowsEmulator):
    """
    A WindowsEmulator that runs on the Icicle VM of `angr.rustylib.winemu`.

    The guest code runs in the VM until the guest code reaches a trap slot, a fault or the end of the budget.
    The API handlers and the exception dispatch stay in Python.
    """

    # The number of instructions that we run between two deadline checks when there is only one thread.
    CHUNK = 50_000_000
    SLEEP_POLL_FAST_FORWARD: bool = False

    WORK_PER_MS = 1_000_000
    CLOCK_READS_PER_MS = 1000

    def __init__(
        self,
        project: Project,
        image_path: str | None = None,
        exports_dir: str | None = None,
        jit: bool = True,
        jit_threshold: int = DEFAULT_JIT_THRESHOLD,
        thread_slice: int = DEFAULT_THREAD_SLICE,
    ):
        """
        :param jit:           Whether we compile hot blocks to native code. We interpret every block otherwise.
        :param jit_threshold: The number of times a block runs before we compile the block.
        :param thread_slice:  The number of instructions in a time slice when several threads exist.
        """
        self.jit = jit
        self.jit_threshold = jit_threshold
        self.thread_slice = thread_slice
        super().__init__(project, image_path, exports_dir)

    def _init_machine(self) -> None:
        self.vm = WinVm(self.is_64bit, PROCESSORS_DIR, self.jit)
        self.vm.jit_threshold = self.jit_threshold
        self._stop_points = _StopPoints(self.vm)
        self.vm.pc = self.project.entry
        self.instructions = 0
        # Windows runs user-mode threads with interrupts enabled, so we set the interrupt flag.
        self.vm.reg_write("if", 1)

    #
    # Memory
    #

    def read(self, addr: int, size: int) -> bytes:
        if size <= 0:
            return b""
        return self.vm.mem_read(addr, size)

    def _store(self, addr: int, data: bytes) -> None:
        try:
            self.vm.mem_write(addr, data)
        except RuntimeError as ex:
            raise SimSegfaultException(addr, "unmapped") from ex

    def patch(self, addr: int, data: bytes) -> None:
        self.write(addr, data)

    def map(self, addr: int, size: int, perms: int = 3) -> None:
        self.vm.mem_map(addr, size, perms)

    def is_mapped(self, addr: int) -> bool:
        return self.vm.mem_perm(addr) is not None

    def perms(self, addr: int) -> int:
        perms = self.vm.mem_perm(addr)
        if perms is None:
            raise SimSegfaultException(addr, "unmapped")
        return perms

    def alloc(self, size: int, perms: int = 3, hint: int | None = None) -> int:
        # Icicle backs a page when the guest first touches the page, so we map the whole allocation at once.
        size = max((size + PAGE - 1) & ~(PAGE - 1), PAGE)
        addr = self.space.reserve(size, self._next_alloc if hint is None else hint)
        if hint is None:
            self._next_alloc = addr + size
        self.map(addr, size, perms | 4)
        self.allocations[addr] = size
        return addr

    def protect(self, addr: int, size: int, perms: int) -> None:
        start = addr & ~(PAGE - 1)
        end = (addr + size + PAGE - 1) & ~(PAGE - 1)
        for page in range(start, end, PAGE):
            self.vm.mem_protect(page, PAGE, perms & ~4 if self._is_watched(page) else perms)

    def _zero_fill_image(self) -> None:
        loader = self.project.loader
        for obj in loader.all_objects:
            if obj is self.main:
                continue
            start = obj.min_addr & ~(PAGE - 1)
            end = (obj.max_addr + PAGE) & ~(PAGE - 1)
            self.map(start, end - start, 3)
            self._copy_loaded(start, end - start)
        self.map(self.image_base, self.image_size, 3)
        self._copy_loaded(self.image_base, self.image_size)
        for section in self.pe.sections:
            chars = section.Characteristics
            perms = (
                (1 if chars & 0x40000000 else 0) | (2 if chars & 0x80000000 else 0) | (4 if chars & 0x20000000 else 0)
            )
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if size:
                self.vm.mem_protect(self.image_base + (section.VirtualAddress & ~(PAGE - 1)), size, perms | 1)
        # The bytes after the raw data of a section and the gaps between sections must read as zero.
        cursor = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        for section in sorted(self.pe.sections, key=lambda s: s.VirtualAddress):
            end = (section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData) + PAGE - 1) & ~(
                PAGE - 1
            )
            if section.VirtualAddress > cursor:
                self.vm.mem_write(
                    self.image_base + cursor,
                    bytes(min(section.VirtualAddress - cursor, PAGE - (cursor & (PAGE - 1)))),
                )
            backed = file_backed_size(section)
            cursor = section.VirtualAddress + backed
            if end > cursor:
                self.vm.mem_write(self.image_base + cursor, bytes(end - cursor))
            cursor = end

    def _copy_loaded(self, start: int, size: int) -> None:
        memory = self.project.loader.memory
        for page in range(start, start + size, PAGE):
            try:
                data = memory.load(page, PAGE)
            except KeyError:
                continue
            if data.strip(b"\0"):
                self.vm.mem_write(page, data)

    def watch_exec(self, start: int, size: int) -> None:
        begin = start & ~(PAGE - 1)
        end = (start + size + PAGE - 1) & ~(PAGE - 1)
        self._watched.append((begin, end))
        for page in range(begin, end, PAGE):
            self.vm.mem_protect(page, PAGE, self.perms(page) & ~4)

    def unwatch_exec(self, addr: int) -> tuple[int, int] | None:
        for idx, (begin, end) in enumerate(self._watched):
            if begin <= addr < end:
                del self._watched[idx]
                for page in range(begin, end, PAGE):
                    self.vm.mem_protect(page, PAGE, self.perms(page) | 4)
                return begin, end
        return None

    #
    # Registers and threads
    #

    @property
    def pc(self) -> int:
        return self.vm.pc

    @property
    def sp(self) -> int:
        return self.vm.reg_read("rsp" if self.is_64bit else "esp")

    def _set_pc(self, addr: int) -> None:
        self.vm.pc = addr

    def _set_sp(self, value: int) -> None:
        self.vm.reg_write("rsp" if self.is_64bit else "esp", value)

    def reg(self, name: str) -> int:
        if name in ("eflags", "rflags"):
            # We only report the status flags, DF, AC and ID, because the Unicorn engine only reports these flags.
            return self.vm.reg_read(name) & 0x240CD5
        return self.vm.reg_read(name)

    def set_reg(self, name: str, value: int) -> None:
        self.vm.reg_write(name, value & ((1 << self.project.arch.bits) - 1))

    def _set_thread_register(self, thread: Thread) -> None:
        if self.is_64bit:
            self.vm.reg_write("gs_base", thread.teb)
        else:
            self.vm.reg_write("fs_base", thread.teb)
            self.vm.reg_write("fs", thread.teb >> 16)

    def _save_registers(self, thread: Thread) -> None:
        self.vm.save_thread(thread.tid)
        thread.registers = thread.tid

    def _load_registers(self, thread: Thread) -> None:
        self.vm.load_thread(thread.tid)

    #
    # Execution
    #

    def _wind(self, instructions: int | None) -> None:
        for _ in range(instructions or 0):
            self.vm.step()

    def _forget_native_failures(self) -> None:
        pass

    def trace_to_api(self, addr: int, max_blocks: int = 20000) -> int | None:
        if self.read(addr, 16) == bytes(16):
            return None
        vm = self.vm
        vm.save_snapshot()
        jit = vm.jit
        vm.jit = False
        try:
            sp = self.sp - 0x400
            self.vm.mem_write(sp, bytes(self.ptr_size))
            self._set_sp(sp)
            vm.pc = addr
            for _ in range(16):
                pc = vm.pc
                slot = self.api_slots.get(pc)
                if slot is not None:
                    if slot[1] != "KiFastSystemCall":
                        return pc if self.sp == sp else None
                    if self.sp != sp - self.ptr_size:
                        return None
                    number = self.reg("eax") & 0xFFFF
                    name = self._syscall_names.get(number)
                    return slot[0].resolve(name, create=False) if name is not None else None
                if self.space.find(pc) is None:
                    return None
                kind = self._trace_run(max_blocks * 8)
                if kind != winemu.EXIT_BREAKPOINT:
                    return None
            return None
        finally:
            vm.jit = jit
            vm.restore_snapshot()

    def _trace_run(self, budget: int) -> int:
        # Zeroed data decodes as `add [eax], al`, so a value that points at zeroed data runs until the budget ends.
        # We stop when the program counter points at zeroed data, and we check after short runs at first.
        vm = self.vm
        step = 64
        while budget > 0:
            if self.read(vm.pc, 16) == bytes(16):
                return winemu.EXIT_OTHER
            step = min(budget, step)
            kind, _, _ = vm.run(step)
            if kind != winemu.EXIT_LIMIT:
                return kind
            budget -= step
            step = min(4 * step, 4096)
        return winemu.EXIT_LIMIT

    def run(self, max_blocks: int | None = None, timeout: float | None = None) -> EmulationStop:
        vm = self.vm
        deadline = None if timeout is None else time.monotonic() + timeout
        # This engine does not count blocks, so we treat each block of the budget as 4 instructions.
        limit = None if max_blocks is None else vm.icount + 4 * max_blocks
        self._stop = None
        if self.load_error is not None:
            return EmulationStop(StopReason.ERROR, self.pc, self.load_error)
        while True:
            if self._stop is not None:
                return self._stop
            addr = vm.pc
            if addr in self.api_slots or addr in self.com.slots:
                self._dispatch_api(addr)
                continue
            continuation = self._continuations.pop(addr, None)
            if continuation is not None:
                self._set_sp(self._saved_sp.pop(addr))
                continuation(self.reg("rax" if self.is_64bit else "eax"))
                continue
            if self.trap_pending:
                self.trap_pending = False
                self._raise_after_step(EXCEPTION_SINGLE_STEP)
                continue
            if self._watched and self._is_watched(addr):
                return EmulationStop(StopReason.EXEC_TRAP, addr)
            if (limit is not None and vm.icount >= limit) or (deadline is not None and time.monotonic() > deadline):
                return EmulationStop(StopReason.BUDGET, addr)
            budget = self.thread_slice if len(self.threads) > 1 else self.CHUNK
            if limit is not None:
                budget = min(budget, limit - vm.icount)
            # We make the time-stamp counter follow the clock that the API handlers keep.
            vm.clock = self.tick
            self._sync_shared_time()
            kind, code, value = vm.run(budget)
            self.blocks = self.instructions = vm.icount
            if kind == winemu.EXIT_BREAKPOINT:
                continue
            if kind == winemu.EXIT_LIMIT:
                pc = vm.pc
                if len(self.threads) > 1 and pc not in self.api_slots and pc not in self._continuations:
                    # The current thread has used up its time slice.
                    self.tick += 16
                    self.switch_thread()
                continue
            if kind == winemu.EXIT_TRAP_FLAG:
                self.exceptions.dispatch(EXCEPTION_SINGLE_STEP, vm.pc)
            elif kind == winemu.EXIT_PRIVILEGED:
                self.exceptions.dispatch(EXCEPTION_PRIV_INSTRUCTION, vm.pc)
            elif kind == winemu.EXIT_EXCEPTION:
                stop = self._on_vm_fault(code, value)
                if stop is not None:
                    return stop
            else:
                return EmulationStop(StopReason.ERROR, vm.pc, f"Icicle exit {kind}/{code}")

    def _raise_after_step(self, code: int) -> None:
        kind, fault, value = self.vm.step()
        if kind == winemu.EXIT_EXCEPTION:
            self._on_vm_fault(fault, value)
            return
        self.exceptions.dispatch(code, self.vm.pc)

    def _on_vm_fault(self, code: int, value: int) -> EmulationStop | None:
        pc = self.vm.pc
        if code in (winemu.FAULT_READ, winemu.FAULT_WRITE):
            self.exceptions.dispatch(EXCEPTION_ACCESS_VIOLATION, pc, (int(code == winemu.FAULT_WRITE), value))
        elif code == winemu.FAULT_EXEC:
            if self._watched and self._is_watched(value):
                self.vm.pc = value
                return EmulationStop(StopReason.EXEC_TRAP, value)
            if self.space.find(value) is not None and self.is_mapped(value):
                # A process without DEP may execute data, so we make the page executable.
                self.protect(value, PAGE, self.perms(value) | 4)
                self.vm.pc = value
            else:
                self.exceptions.dispatch(EXCEPTION_ACCESS_VIOLATION, pc, (8, value))
        elif code == winemu.FAULT_DIVIDE:
            self.exceptions.dispatch(EXCEPTION_INT_DIVIDE_BY_ZERO, pc)
        elif code == winemu.FAULT_INVALID:
            opcode = self.read(pc, 1)[0]
            self.exceptions.dispatch(
                EXCEPTION_PRIV_INSTRUCTION if opcode in _PRIVILEGED_OPCODES else EXCEPTION_ILLEGAL_INSTRUCTION, pc
            )
        elif code == winemu.FAULT_SYSCALL:
            self._on_trap_instruction(pc)
        else:
            return EmulationStop(StopReason.ERROR, pc, f"Icicle exception {code >> 8:#x} at {value:#x}")
        return None

    def _on_trap_instruction(self, pc: int) -> None:
        code = self.read(pc, 2)
        if code[0] == 0xCC:
            self.exceptions.dispatch(EXCEPTION_BREAKPOINT, pc)
            return
        next_pc = self.vm.reg_read("next_pc")
        if code[0] == 0xF1:
            self._set_pc(next_pc)
            self.exceptions.dispatch(EXCEPTION_SINGLE_STEP, next_pc)
            return
        if code in (b"\x0f\x05", b"\x0f\x34", b"\xcd\x2e"):
            self._set_pc(next_pc)
            self._on_syscall_instruction()
            return
        if code == b"\xcd\x03":
            self.exceptions.dispatch(EXCEPTION_BREAKPOINT, pc)
            return
        if code == b"\xcd\x2d":
            # Without a debugger, Windows reports the breakpoint exception of `int 0x2d` at the next instruction.
            self._set_pc(next_pc)
            self.exceptions.dispatch(EXCEPTION_BREAKPOINT, next_pc)
            return
        # User mode may not raise any other software interrupt, so we dispatch an access violation.
        self.exceptions.dispatch(EXCEPTION_ACCESS_VIOLATION, pc, (0, 0xFFFFFFFF))
