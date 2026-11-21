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
_MAX_FRAMES = 128
_X86_CONTEXT_SIZE = 0x2CC
_X64_CONTEXT_SIZE = 0x4D0
_X86_REGS = (("edi", 0x9C), ("esi", 0xA0), ("ebx", 0xA4), ("edx", 0xA8), ("ecx", 0xAC), ("eax", 0xB0), ("ebp", 0xB4),
             ("eip", 0xB8), ("eflags", 0xC0), ("esp", 0xC4))  # fmt: skip
_X64_REGS = (("rax", 0x78), ("rcx", 0x80), ("rdx", 0x88), ("rbx", 0x90), ("rsp", 0x98), ("rbp", 0xA0), ("rsi", 0xA8),
             ("rdi", 0xB0), ("r8", 0xB8), ("r9", 0xC0), ("r10", 0xC8), ("r11", 0xD0), ("r12", 0xD8), ("r13", 0xE0),
             ("r14", 0xE8), ("r15", 0xF0), ("rip", 0xF8))  # fmt: skip


# register numbers and slot counts used by x64 unwind codes
_UNWIND_REGS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
                "r15")  # fmt: skip
_UNWIND_OP_SLOTS = {1: 2, 4: 2, 5: 3, 6: 2, 7: 3, 8: 2, 9: 3}


class ExceptionDispatcher:
    """
    User-mode exception dispatch: vectored handlers, frame-based handlers (the x86 SEH chain, or the x64 function
    tables), then the unhandled-exception filter.
    """

    def __init__(self, emu: WindowsEmulator):
        self.emu = emu
        self.vectored: list[int] = []
        self.unhandled_filter = 0
        self.count = 0
        # addresses of the EXCEPTION_POINTERS and CONTEXT of the exception being dispatched
        self.pointers = 0
        self.context = 0
        self._dynamic_tables: list[tuple[int, int, int]] = []

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

    def read_registers(self, addr: int) -> dict[str, int]:
        """
        The general-purpose registers of a 64-bit CONTEXT.
        """
        data = self.emu.read(addr + 0x78, 0x88)
        return {name: struct.unpack_from("<Q", data, off - 0x78)[0] for name, off in _X64_REGS}

    def write_registers(self, addr: int, regs: dict[str, int]) -> None:
        for name, off in _X64_REGS:
            self.emu.write(addr + off, struct.pack("<Q", regs[name]))

    #
    # x64 function tables and unwinding
    #

    def add_function_table(self, table: int, count: int, base: int) -> None:
        self._dynamic_tables.append((base, table, count))

    def remove_function_table(self, table: int) -> None:
        self._dynamic_tables = [entry for entry in self._dynamic_tables if entry[1] != table]

    def lookup_function(self, pc: int) -> tuple[int, int] | None:
        """
        Find the RUNTIME_FUNCTION that covers pc. Returns (image base, address of the entry).
        """
        emu = self.emu
        tables = list(self._dynamic_tables)
        directory = emu.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if directory.VirtualAddress and emu.image_base <= pc < emu.image_base + emu.image_size:
            tables.append((emu.image_base, emu.image_base + directory.VirtualAddress, directory.Size // 12))
        for base, table, count in tables:
            rva = pc - base
            if not 0 <= rva < 1 << 32:
                continue
            lo, hi = 0, count
            while lo < hi:
                mid = (lo + hi) // 2
                begin, end = struct.unpack("<II", emu.read(table + 12 * mid, 8))
                if rva < begin:
                    hi = mid
                elif rva >= end:
                    lo = mid + 1
                else:
                    return base, table + 12 * mid
        return None

    def virtual_unwind(self, base: int, entry: int, regs: dict[str, int]) -> tuple[int | None, int, int]:
        """
        Undo the effects of the prologue of the function described by a RUNTIME_FUNCTION: regs become the caller's.
        Returns (language handler or None, address of its data, establisher frame). Epilogues are not recognized.
        """
        emu = self.emu
        pc = regs["rip"]
        handler: int | None = None
        handler_data = 0
        establisher = regs["rsp"]
        first = True
        for _ in range(32):
            begin, _, info_rva = struct.unpack("<III", emu.read(entry, 12))
            if info_rva & 1:
                entry = base + (info_rva & ~1)
                continue
            info = base + info_rva
            version_flags, prolog_size, count, frame_byte = emu.read(info, 4)
            flags = version_flags >> 3
            frame_reg = frame_byte & 0xF
            frame_offset = (frame_byte >> 4) * 16
            codes = emu.read(info + 4, 2 * count)
            offset = pc - (base + begin) if first else 1 << 32
            # the frame pointer only counts once the prologue has set it
            frame = regs["rsp"]
            if frame_reg and (
                offset >= prolog_size
                or any(codes[2 * i + 1] & 0xF == 3 and offset >= codes[2 * i] for i in range(count))
            ):
                frame = regs[_UNWIND_REGS[frame_reg]] - frame_offset
            if first:
                establisher = frame
            machine_frame = False
            idx = 0
            while idx < count:
                code_offset, op_byte = codes[2 * idx], codes[2 * idx + 1]
                op, op_info = op_byte & 0xF, op_byte >> 4
                slots = _UNWIND_OP_SLOTS.get(op, 1)
                if op == 1 and op_info:
                    slots = 3
                operand = 0
                if slots == 2:
                    operand = struct.unpack_from("<H", codes, 2 * idx + 2)[0]
                elif slots == 3 and 2 * idx + 6 <= len(codes):
                    operand = struct.unpack_from("<I", codes, 2 * idx + 2)[0]
                idx += slots
                if offset < code_offset:
                    continue
                if op == 0:  # UWOP_PUSH_NONVOL
                    regs[_UNWIND_REGS[op_info]] = emu.read_ptr(regs["rsp"])
                    regs["rsp"] += 8
                elif op == 1:  # UWOP_ALLOC_LARGE
                    regs["rsp"] += operand if op_info else operand * 8
                elif op == 2:  # UWOP_ALLOC_SMALL
                    regs["rsp"] += op_info * 8 + 8
                elif op == 3:  # UWOP_SET_FPREG
                    regs["rsp"] = regs[_UNWIND_REGS[frame_reg]] - frame_offset
                elif op == 4:  # UWOP_SAVE_NONVOL
                    regs[_UNWIND_REGS[op_info]] = emu.read_ptr(frame + operand * 8)
                elif op == 5:  # UWOP_SAVE_NONVOL_FAR
                    regs[_UNWIND_REGS[op_info]] = emu.read_ptr(frame + operand)
                elif op == 10:  # UWOP_PUSH_MACHFRAME
                    top = regs["rsp"] + (8 if op_info else 0)
                    regs["rip"] = emu.read_ptr(top)
                    regs["rsp"] = emu.read_ptr(top + 0x18)
                    machine_frame = True
            tail = info + 4 + 2 * ((count + 1) & ~1)
            if first and flags & 3:
                handler = base + emu.read_u32(tail)
                handler_data = tail + 4
            first = False
            if flags & 4 and not machine_frame:  # UNW_FLAG_CHAININFO: the rest is described by a parent entry
                entry = tail
                continue
            if not machine_frame:
                regs["rip"] = emu.read_ptr(regs["rsp"])
                regs["rsp"] += 8
            break
        return handler, handler_data, establisher

    def _unwind_frame(self, regs: dict[str, int]) -> tuple[int | None, int, int, int, int]:
        """
        Step regs to the caller. Returns (language handler, handler data, establisher frame, image base, entry).
        """
        found = self.lookup_function(regs["rip"])
        if found is None:
            # a leaf function: only the return address is on the stack
            frame = regs["rsp"]
            regs["rip"] = self.emu.read_ptr(frame)
            regs["rsp"] = frame + 8
            return None, 0, frame, 0, 0
        handler, data, establisher = self.virtual_unwind(found[0], found[1], regs)
        return handler, data, establisher, found[0], found[1]

    def _on_stack(self, regs: dict[str, int]) -> bool:
        thread = self.emu.thread
        return thread.stack_base - self.emu.STACK_SIZE <= regs["rsp"] < thread.stack_base and regs["rip"] != 0

    def unwind_to(self, target_frame: int, target_ip: int, return_value: int) -> None:
        """
        RtlUnwindEx for the exception being dispatched: resume at target_ip in the function whose establisher frame
        is target_frame. Termination handlers of the frames in between are not run.
        """
        emu = self.emu
        regs = self.read_registers(self.context)
        for _ in range(_MAX_FRAMES):
            if not self._on_stack(regs):
                break
            before = dict(regs)
            establisher = self._unwind_frame(regs)[2]
            if establisher == target_frame:
                regs = before
                break
        else:
            emu.stop(StopReason.ERROR, f"unwind target frame {target_frame:#x} not found")
            return
        regs["rip"] = target_ip
        regs["rax"] = return_value
        for name, value in regs.items():
            emu.set_reg(name, value)

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
        self.pointers = pointers
        self.context = context

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

        def try_frames(regs: dict[str, int], depth: int) -> None:
            # x64: walk the call stack through the function tables, offering the exception to each language handler
            while depth < _MAX_FRAMES and self._on_stack(regs):
                depth += 1
                control_pc = regs["rip"]
                handler, data, establisher, base, entry = self._unwind_frame(regs)
                if handler is None:
                    continue
                dispatcher = frame + 0x600
                emu.write(
                    dispatcher,
                    struct.pack("<10Q", control_pc, base, entry, establisher, 0, context, handler, data, 0, 0),
                )

                def after_handler(result: int, regs: dict[str, int] = regs, depth: int = depth) -> None:
                    self.pointers = pointers
                    self.context = context
                    if result & 0xFFFFFFFF == 0:
                        self.restore_context(context)
                    else:
                        try_frames(regs, depth)

                emu.call_guest(handler, (record, establisher, context, dispatcher), after_handler)
                return
            try_seh(0)

        def try_vectored(result: int) -> None:
            if result & 0xFFFFFFFF == _CONTINUE_EXECUTION:
                self.restore_context(context)
            elif vectored:
                emu.call_guest(vectored.pop(0), (pointers,), try_vectored)
            elif emu.is_64bit:
                try_frames(self.read_registers(context), 0)
            else:
                try_seh(seh_frame)

        try_vectored(0)
