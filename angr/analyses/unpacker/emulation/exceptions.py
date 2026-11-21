from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from .stops import StopReason

if TYPE_CHECKING:
    from .environment import WindowsEmulator

EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
EXCEPTION_PRIV_INSTRUCTION = 0xC0000096
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094

_CONTINUE_EXECUTION = 0xFFFFFFFF
_TRAP_FLAG = 0x100
_X86_CONTEXT_SIZE = 0x2CC
_X64_CONTEXT_SIZE = 0x4D0
_X86_REGS = (("edi", 0x9C), ("esi", 0xA0), ("ebx", 0xA4), ("edx", 0xA8), ("ecx", 0xAC), ("eax", 0xB0), ("ebp", 0xB4),
             ("eip", 0xB8), ("eflags", 0xC0), ("esp", 0xC4))  # fmt: skip
_X64_REGS = (("rax", 0x78), ("rcx", 0x80), ("rdx", 0x88), ("rbx", 0x90), ("rsp", 0x98), ("rbp", 0xA0), ("rsi", 0xA8),
             ("rdi", 0xB0), ("r8", 0xB8), ("r9", 0xC0), ("r10", 0xC8), ("r11", 0xD0), ("r12", 0xD8), ("r13", 0xE0),
             ("r14", 0xE8), ("r15", 0xF0), ("rip", 0xF8))  # fmt: skip


class ExceptionDispatcher:
    """
    User-mode exception dispatch: vectored handlers, x86 frame-based SEH, then the unhandled-exception filter.
    """

    def __init__(self, emu: WindowsEmulator):
        self.emu = emu
        self.vectored: list[int] = []
        self.unhandled_filter = 0
        self.count = 0

    def write_context(self, addr: int, pc: int) -> None:
        emu = self.emu
        if emu.is_64bit:
            emu.write(addr, bytes(_X64_CONTEXT_SIZE))
            emu.write(addr + 0x30, struct.pack("<I", 0x10001F))
            emu.write(addr + 0x38, struct.pack("<HHHHHH", 0x33, 0x2B, 0x2B, 0x53, 0x2B, 0x2B))
            emu.write(addr + 0x44, struct.pack("<I", emu.reg("rflags") & 0xFFFFFFFF))
            for name, off in _X64_REGS:
                emu.write(addr + off, struct.pack("<Q", pc if name == "rip" else emu.reg(name)))
        else:
            emu.write(addr, bytes(_X86_CONTEXT_SIZE))
            emu.write(addr, struct.pack("<I", 0x1003F))
            emu.write(addr + 0x8C, struct.pack("<IIII", 0, 0x3B, 0x23, 0x23))
            emu.write(addr + 0xBC, struct.pack("<I", 0x1B))
            emu.write(addr + 0xC8, struct.pack("<I", 0x23))
            for name, off in _X86_REGS:
                emu.write(addr + off, struct.pack("<I", pc if name == "eip" else emu.reg(name)))

    def restore_context(self, addr: int) -> None:
        emu = self.emu
        if emu.is_64bit:
            for name, off in _X64_REGS:
                emu.set_reg(name, struct.unpack("<Q", emu.read(addr + off, 8))[0])
            flags = emu.read_u32(addr + 0x44)
            emu.set_reg("rflags", flags)
        else:
            for name, off in _X86_REGS:
                emu.set_reg(name, emu.read_u32(addr + off))
            flags = emu.read_u32(addr + 0xC0)
        emu.trap_pending = bool(flags & _TRAP_FLAG)

    def dispatch(self, code: int, pc: int, info: tuple[int, ...] = (), flags: int = 0) -> None:
        """
        Deliver an exception raised at pc. Control resumes wherever the handlers decide.
        """
        emu = self.emu
        self.count += 1
        if self.count > 100000:
            emu.stop(StopReason.ERROR, "exception storm")
            return
        ptr = emu.ptr_size
        frame = (emu.sp - 0x1000) & ~0xF
        if emu.space.find(frame - 0x1000) is None or emu.space.find(frame + 0x800) is None:
            emu.stop(StopReason.ERROR, f"exception {code:#x} at {pc:#x} with an unusable stack ({emu.sp:#x})")
            return
        context = frame + 0x100
        record = frame + 0x10
        self.write_context(context, pc)
        emu.write(record, struct.pack("<II", code, flags))
        emu.write_ptr(record + 8, 0)
        emu.write_ptr(record + 8 + ptr, pc)
        emu.write(record + 8 + 2 * ptr, struct.pack("<I", len(info)))
        for idx, value in enumerate(info):
            emu.write_ptr(record + 8 + 3 * ptr + ptr * idx, value)
        pointers = frame
        emu.write_ptr(pointers, record)
        emu.write_ptr(pointers + ptr, context)
        emu.set_reg("rsp" if emu.is_64bit else "esp", frame - 0x40)

        vectored = list(self.vectored)
        seh_frame = emu.read_ptr(emu.teb) if not emu.is_64bit else 0

        def unhandled() -> None:
            emu.stop(StopReason.ERROR, f"unhandled exception {code:#x} at {pc:#x}")

        def after_filter(result: int) -> None:
            if result & 0xFFFFFFFF == _CONTINUE_EXECUTION:
                self.restore_context(context)
            else:
                unhandled()

        def try_seh(frame_addr: int) -> None:
            if frame_addr in (0, 0xFFFFFFFF) or emu.space.find(frame_addr) is None:
                if self.unhandled_filter:
                    emu.call_guest(self.unhandled_filter, (pointers,), after_filter)
                else:
                    unhandled()
                return

            def after_handler(result: int) -> None:
                if result & 0xFFFFFFFF == 0:
                    self.restore_context(context)
                else:
                    try_seh(emu.read_ptr(frame_addr))

            emu.call_guest(emu.read_ptr(frame_addr + 4), (record, frame_addr, context, frame + 0x80), after_handler)

        def try_vectored(result: int) -> None:
            if result & 0xFFFFFFFF == _CONTINUE_EXECUTION:
                self.restore_context(context)
            elif vectored:
                emu.call_guest(vectored.pop(0), (pointers,), try_vectored)
            else:
                try_seh(seh_frame)

        try_vectored(0)
