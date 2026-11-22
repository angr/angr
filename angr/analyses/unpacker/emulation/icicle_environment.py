from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import time

import pypcode

from angr.errors import SimSegfaultException
from angr.rustylib import winemu
from angr.rustylib.winemu import WinVm

from .environment import PAGE, WindowsEmulator
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

PROCESSORS_DIR = os.path.join(os.path.dirname(pypcode.__file__), "processors")
# fixes to Ghidra's x86 spec: pushf bit 1; SHR/SHRD by one set OF from the operand's sign; for shift and rotate counts above one,
# where OF is undefined, OF follows QEMU (the engine the Unicorn path runs on)
_IA_PATCHES = (
    (
        " conditionalAssign(OF, count==1, 0, (op1 s< 0)); ",
        " conditionalAssign(OF, count==0, OF, ((op1 >> (count - 1)) ^ result) s< 0); ",
    ),
    (
        " conditionalAssign(OF, count==1, 0, ((op1 s< 0) ^ (result s< 0))); ",
        " conditionalAssign(OF, count==1, ((op1 s< 0) ^ (result s< 0)), OF); ",
    ),
    (
        " conditionalAssign(OF, count==1, CF ^ (result s< 0), OF);\n}\n\nmacro sarflags",
        " conditionalAssign(OF, count==0, OF, CF ^ (result s< 0));\n}\n\nmacro sarflags",
    ),
    (" conditionalAssign(OF, count==1, 0, OF); ", " conditionalAssign(OF, count==0, OF, 0); "),
    # shifts by a non-zero count clear AF (as QEMU does), by zero keep it
    (
        " PF = (!notzero & PF) | (notzero & newPF);\n # AF not implemented",
        " PF = (!notzero & PF) | (notzero & newPF);\n AF = !notzero & AF;",
    ),
    # pushf: the reserved bit 1 always reads as one
    (
        "| (0x0004 * zext(PF&1)) | (0x0001 * zext(CF&1));",
        "| (0x0004 * zext(PF&1)) | 0x0002 | (0x0001 * zext(CF&1));",
    ),
    (
        " conditionalAssign(OF, count==1, CF ^ (result s< 0), OF); \n}\n\nmacro rorflags",
        " conditionalAssign(OF, count==0, OF, CF ^ (result s< 0)); \n}\n\nmacro rorflags",
    ),
    (
        " conditionalAssign(OF, count==1, CF ^ ((result << 1) s< 0), OF); ",
        " conditionalAssign(OF, count==0, OF, CF ^ ((result << 1) s< 0)); ",
    ),
)
# xchg m32, r32 in 64-bit mode: the register's upper half is cleared like for every 32-bit write
_XCHG_M32 = (
    (
        "opsize=1 & byte=0x87; m32 & Reg32 ...        \n{ \n  build xacq_xrel_prefx;\n  build alwaysLock;\n  build m32;\n"
        "  local tmp = m32; \n  m32 = Reg32; \n  Reg32 = tmp; \n"
    ),
    (
        "opsize=1 & byte=0x87; (check_Reg32_dest & Reg32) ... & m32\n{ \n  build xacq_xrel_prefx;\n  build alwaysLock;\n"
        "  build m32;\n  local tmp = m32; \n  m32 = Reg32; \n  Reg32 = tmp; \n  build check_Reg32_dest;\n"
    ),
)
# an address-size prefix (16-bit addressing) does not change the stack's width, which the SS descriptor sets (32 bits
# in a flat process); SLEIGH pushes and pops through SP for it
_STACK16 = tuple(
    (
        f"macro push2{n}(x) {{\n  mysave:{n} = x;\n  SP = SP{' -' if n == 2 else '-'}{n};\n"
        + f"  tmp:$(SIZE) = segment(SS,SP);\n  *:{n} tmp = mysave;\n}}",
        f"macro push2{n}(x) {{\n  mysave:{n} = x;\n  $(STACKPTR) = $(STACKPTR) - {n};\n  *:{n} $(STACKPTR) = mysave;\n}}",
    )
    for n in (2, 4, 8)
) + tuple(
    (
        f"macro pop2{n}(x) {{\n  tmp:$(SIZE) = segment(SS,SP);\n  x = *:{n} tmp;\n  SP = SP+{n};\n}}",
        f"macro pop2{n}(x) {{\n  x = *:{n} $(STACKPTR);\n  $(STACKPTR) = $(STACKPTR) + {n};\n}}",
    )
    for n in (2, 4, 8)
)


def _checked(query: str, operand: str, assign: str) -> str:
    # bit 32 of the query's result says whether the selector is visible; an invisible one leaves the destination
    return f"tmp:8 = {query}({operand}); ZF = tmp[32,1]; if (ZF == 0) goto <done>; {assign} <done>"


# lsl and lar: SegmentLimit / SegmentRights return the 32-bit limit or the access rights and the visibility bit;
# verr / verw get their operand
_LAR = ":LAR Reg{0},rm{3}     is {1}vexMode=0 & opsize={2} & byte=0xf; byte=0x2; rm{3} & Reg{0} ..."
_DESCRIPTORS = (
    (
        _LAR.format(16, "", 0, 16) + "  { Reg16 = rm16 & 0xff00; ZF=1; }",
        "define pcodeop SegmentRights;\n"
        + _LAR.format(16, "", 0, 16)
        + f" {{ {_checked('SegmentRights', 'rm16', 'Reg16 = tmp:2;')} }}",
    ),
    (
        _LAR.format(32, "", 1, 32)
        + " & check_Reg32_dest ... { Reg32 = rm32 & 0xffff00; build check_Reg32_dest; ZF=1; }",
        _LAR.format(32, "", 1, 32)
        + f" & check_Reg32_dest ... {{ {_checked('SegmentRights', 'rm32', 'Reg32 = tmp:4; build check_Reg32_dest;')} }}",
    ),
    (
        _LAR.format(64, "$(LONGMODE_ON) & ", 2, 32) + " { Reg64 = zext( rm32 & 0xffff00 ); ZF=1; }",
        _LAR.format(64, "$(LONGMODE_ON) & ", 2, 32)
        + f" {{ {_checked('SegmentRights', 'rm32', 'Reg64 = zext(tmp:4);')} }}",
    ),
    ("{ ZF = verr(); }", "{ ZF = verr(rm16); }"),
    ("{ ZF = verw(); }", "{ ZF = verw(rm16); }"),
    (
        "  tmp:3 = SegmentLimit(rm16);\n  Reg16 = tmp:2;\n  ZF = tmp[16,1];\n",
        f"  {_checked('SegmentLimit', 'rm16', 'Reg16 = tmp:2;')}\n",
    ),
    (
        "  tmp:3 = SegmentLimit(rm32);\n  Reg32 = zext(tmp:2);\n  build check_Reg32_dest;\n  ZF = tmp[16,1];\n",
        f"  {_checked('SegmentLimit', 'rm32', 'Reg32 = tmp:4; build check_Reg32_dest;')}\n",
    ),
    (
        "  tmp:3 = SegmentLimit(rm32);\n  Reg64 = zext(tmp:2);\n  ZF = tmp[16,1];\n",
        f"  {_checked('SegmentLimit', 'rm32', 'Reg64 = zext(tmp:4);')}\n",
    ),
)
# MMX / SSE2
_SSE2 = (
    # the masked moves merge into memory: pass its old content to the helper
    ("{ maskMovDI = maskmovdqu(XmmReg1, XmmReg2); }", "{ maskMovDI = maskmovdqu(XmmReg1, XmmReg2, maskMovDI); }"),
    (
        "{ maskMovDI = MaskedMoveQWord(mmxreg1, mmxreg2); }",
        "{ maskMovDI = MaskedMoveQWord(mmxreg1, mmxreg2, maskMovDI); }",
    ),
    # cvtps2pi stored the rounded floats instead of integers
    ("  mmxreg[0,32] = round(m[0,32]);", "  mmxreg[0,32] = trunc(round(m[0,32]));"),
    ("  mmxreg[32,32] = round(m[32,32]);", "  mmxreg[32,32] = trunc(round(m[32,32]));"),
    ("  mmxreg1[0,32] = round(XmmReg2[0,32]);", "  mmxreg1[0,32] = trunc(round(XmmReg2[0,32]));"),
    ("  mmxreg1[32,32] = round(XmmReg2[32,32]);", "  mmxreg1[32,32] = trunc(round(XmmReg2[32,32]));"),
    # psrad xmm: the count is the whole low quadword
    ("    local count:4 = XmmReg2[0,32];", "    local count:8 = XmmReg2[0,64];"),
    ("    local count:4 = m[0,32];", "    local count:8 = m[0,64];"),
)
# extractps stores 32 bits whatever the mode (a register destination is zero-extended by the 32-bit form)
_SSE41 = (
    (
        ":EXTRACTPS rm64, XmmReg, imm8  is $(LONGMODE_ON) & vexMode=0 & bit64=1 & $(PRE_66) & byte=0x0F; byte=0x3A;"
        " byte=0x17; XmmReg ... & rm64; imm8 { rm64 = extractps(XmmReg, imm8:8); }",
        "",
    ),
)
# pcmpestri / pcmpestrm: tell the helper whether the lengths are 64 bits wide (REX.W)
_SSE42 = (
    (", EAX, EDX);", ", EAX, EDX, 0:1);"),
    (", RAX, RDX);", ", RAX, RDX, 1:1);"),
)
# x87 values are doubles under Icicle: convert 80-bit memory operands; fprem went through a 10-byte integer
_X87 = (
    (
        "define pcodeop segment;",
        "define pcodeop segment;\ndefine pcodeop f80_decode;\ndefine pcodeop f80_encode;\ndefine pcodeop fprem;\n"
        "define pcodeop fprem1;",
    ),
    (
        "    fpushv(m80fp); ",
        "    fpushv(m80fp); ST0 = f80_decode(ST0); ",
    ),
    ("    fpopv(m80fp); ", "    local ext:10; fpopv(ext); local raw:10 = f80_encode(ext); m80fp = raw; "),
    ("    ST0 = from_bcd(m80); ", "    local raw:10 = m80; ST0 = from_bcd(raw); "),
    ("    m80 = to_bcd(ST0); ", "    local raw:10 = to_bcd(ST0); m80 = raw; "),
    # fxam: infinities and NaNs get their own classes
    ("  C0 = nan(ST0);", "  C0 = nan(ST0) || (((ST0 f+ ST0) f== ST0) && (ST0 f!= fzero));"),
    ("  C2 = ( ST0 f!= fzero );", "  C2 = !nan(ST0) && ( ST0 f!= fzero );"),
    (
        ":FPREM          is vexMode=0 & byte=0xD9; byte=0xF8\n{\n    FPUInstructionPointer = inst_start;\n"
        "    local tmp = ST0 f/ ST1;\n    tmp = trunc(tmp);\n    tmp = tmp f* ST1;\n    ST0 = ST0 f- tmp;\n",
        ":FPREM          is vexMode=0 & byte=0xD9; byte=0xF8\n{\n    FPUInstructionPointer = inst_start;\n"
        "    ST0 = fprem(ST0, ST1);\n",
    ),
    (
        "    local tmp = ST0 f/ ST1;\n    tmp = round(tmp);\n    tmp = tmp f* ST1;\n    ST0 = ST0 f- tmp;\n",
        "    ST0 = fprem1(ST0, ST1);\n",
    ),
)
# bsf / bsr of zero: ZF is set and the destination stays as it was, upper half of a 64-bit register included (AMD
# documents this; Intel processors behave the same)
_BIT_SCANS = (
    ("    if ( ZF == 1 ) goto <done>;", "    if ( ZF == 1 ) goto <zero>;"),
    ("    Reg16 = bitIndex;", "    Reg16 = bitIndex;\n<zero>"),
    (
        "    Reg32 = bitIndex;\n    build check_Reg32_dest;",
        "    Reg32 = bitIndex;\n    build check_Reg32_dest;\n<zero>",
    ),
    ("    Reg64 = bitIndex;", "    Reg64 = bitIndex;\n<zero>"),
)
# mul / imul leave SF, ZF and PF undefined; Intel processors since the Pentium 4 (and QEMU) set them from the low
# half of the product
_MULTIPLY_FLAGS = (
    (
        "macro imultflags(low,total){\n  CF = sext(low) != total;\n  OF = CF;\n",
        "macro imultflags(low,total){\n  CF = sext(low) != total;\n  OF = CF;\n  resultflags(low);\n",
    ),
    ("multflags(AH); }", "multflags(AH); resultflags(AL); }"),
    ("multflags(DX); }", "multflags(DX); resultflags(AX); }"),
    (
        "multflags(EDX);  EAX=tmp(0); build check_EAX_dest;  }",
        "multflags(EDX);  EAX=tmp(0); build check_EAX_dest; resultflags(EAX); }",
    ),
    ("multflags(RDX); }", "multflags(RDX); resultflags(RAX); }"),
)
# ASCII adjusts: aaa / aas carry into AH as "AX +- 0x106" does; aam / aad set SF, ZF and PF from AL
_ASCII_ADJUST = (
    (
        "{ local car = ((AL & 0xf) > 9) | AF; AL = (AL+6*car)&0xf; AH=AH+car; CF=car; AF=car; }",
        "{ local car = ((AL & 0xf) > 9) | AF; local wrap = car & (AL > 0xf9); AL = (AL+6*car)&0xf; AH=AH+car+wrap;"
        " CF=car; AF=car; }",
    ),
    (
        "{ local car = ((AL & 0xf) > 9) | AF; AL = (AL-6*car)&0xf; AH=AH-car; CF=car; AF=car; }",
        "{ local car = ((AL & 0xf) > 9) | AF; local wrap = car & (AL < 6); AL = (AL-6*car)&0xf; AH=AH-car-wrap;"
        " CF=car; AF=car; }",
    ),
    ("{ AL = AL + imm8*AH; AH=0; resultflags(AX); }", "{ AL = AL + imm8*AH; AH=0; resultflags(AL); }"),
    ("{ AH = AL/imm8; AL = AL % imm8; resultflags(AX); }", "{ AH = AL/imm8; AL = AL % imm8; resultflags(AL); }"),
)
# regex substitutions inside every constructor of a mnemonic: these conversions round (MXCSR's default, to nearest
# even) where the spec truncates
_CONSTRUCTOR_PATCHES = tuple(
    (name, r"trunc\((.*?)\);", r"trunc(round(\1));") for name in ("CVTPS2DQ", "CVTPD2DQ", "CVTPD2PI")
)
_SLEIGH_PATCHES: tuple[tuple[str, str, str], ...] = (
    *(("ia.sinc", old, new) for old, new in _IA_PATCHES),
    *(("ia.sinc", old, new) for old, new in _STACK16),
    *(("ia.sinc", old, new) for old, new in _DESCRIPTORS),
    *(("ia.sinc", old, new) for old, new in _SSE2),
    *(("ia.sinc", old, new) for old, new in _SSE41),
    *(("ia.sinc", old, new) for old, new in _SSE42),
    *(("ia.sinc", old, new) for old, new in _X87),
    *(("ia.sinc", old, new) for old, new in _BIT_SCANS),
    *(("ia.sinc", old, new) for old, new in _MULTIPLY_FLAGS),
    *(("ia.sinc", old, new) for old, new in _ASCII_ADJUST),
    ("lockable.sinc", *_XCHG_M32),
)


def patched_processors() -> str:
    """
    A copy of pypcode's x86 SLEIGH files with _SLEIGH_PATCHES applied, made once per pypcode version.
    """
    digest = hashlib.sha256(repr((_SLEIGH_PATCHES, _CONSTRUCTOR_PATCHES)).encode()).hexdigest()[:12]
    root = os.path.join(tempfile.gettempdir(), f"angr-unpacker-sleigh-{pypcode.__version__}-{digest}")
    languages = os.path.join(root, "x86", "data", "languages")
    if os.path.isdir(languages):
        return root
    staging = tempfile.mkdtemp(prefix=root + ".")
    shutil.copytree(os.path.join(PROCESSORS_DIR, "x86"), os.path.join(staging, "x86"))
    for name in sorted({name for name, _, _ in _SLEIGH_PATCHES}):
        path = os.path.join(staging, "x86", "data", "languages", name)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for patched, old, new in _SLEIGH_PATCHES:
            if patched == name:
                assert old in text, old
                text = text.replace(old, new)
        if name == "ia.sinc":
            for mnemonic, pattern, repl in _CONSTRUCTOR_PATCHES:
                text, count = re.subn(
                    rf"^:{mnemonic} .*?^\}}",
                    lambda m, pattern=pattern, repl=repl: re.sub(pattern, repl, m.group(0)),
                    text,
                    flags=re.MULTILINE | re.DOTALL,
                )
                assert count, mnemonic
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    try:
        os.rename(staging, root)
    except OSError:
        # another process won the race
        shutil.rmtree(staging, ignore_errors=True)
    return root


_PRIVILEGED_OPCODES = frozenset((0xF4, 0xFA, 0xFB, 0xE4, 0xE5, 0xE6, 0xE7, 0xEC, 0xED, 0xEE, 0xEF, 0x6C, 0x6D, 0x6E,
                                 0x6F))  # fmt: skip


class _StopPoints(set[int]):
    """
    The emulator's stop points, mirrored as VM breakpoints.
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


class IcicleWindowsEmulator(WindowsEmulator):
    """
    WindowsEmulator on an Icicle VM driven from Rust (angr.rustylib.winemu). Guest code runs natively until it
    reaches a trap slot, a fault or the end of its budget; the API handlers and exception dispatch stay in Python.
    """

    # instructions per time slice when several threads exist, and between deadline checks otherwise
    SLICE = int(os.environ.get("ANGR_UNPACKER_ICICLE_SLICE", "4000000"))
    CHUNK = 50_000_000

    def _init_machine(self) -> None:
        self.vm = WinVm(self.is_64bit, patched_processors(), os.environ.get("ANGR_UNPACKER_ICICLE_JIT", "1") != "0")
        # protector code mostly runs a few times after it is decrypted; compiling it all costs ~1 ms per block
        self.vm.jit_threshold = int(os.environ.get("ANGR_UNPACKER_ICICLE_JIT_THRESHOLD", "32"))
        self._stop_points = _StopPoints(self.vm)
        self.vm.pc = self.project.entry
        self.instructions = 0
        # interrupts enabled, as in any user-mode thread
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
        # Icicle backs pages on first touch, so nothing is lazy here
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
        # as on the Unicorn path: file bytes past a section's virtual size and the gaps between sections read as zero
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
            backed = min(section.SizeOfRawData, section.Misc_VirtualSize or section.SizeOfRawData)
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
            # what the Unicorn path reports (VEX's flags thunk): status flags, DF, AC and ID only
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
        vm = self.vm
        vm.save_snapshot()
        # short runs over mostly new code: compiling each block costs more than interpreting it
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
                        return pc
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
        # values that point at zeroed data slide through `add [eax], al` until the budget ends; translating each
        # new instruction is what costs here, so give up on such slides early
        vm = self.vm
        while budget > 0:
            step = min(budget, 4096)
            kind, _, _ = vm.run(step)
            if kind != winemu.EXIT_LIMIT:
                return kind
            budget -= step
            if vm.mem_read(vm.pc, 16) == bytes(16):
                return winemu.EXIT_OTHER
        return winemu.EXIT_LIMIT

    def run(self, max_blocks: int | None = None, timeout: float | None = None) -> EmulationStop:
        vm = self.vm
        deadline = None if timeout is None else time.monotonic() + timeout
        # blocks are not counted on this engine; a budget is taken as about 4 instructions per block
        limit = None if max_blocks is None else vm.icount + 4 * max_blocks
        self._stop = None
        while True:
            if self._stop is not None:
                return self._stop
            addr = vm.pc
            if addr in self.api_slots:
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
            budget = self.SLICE if len(self.threads) > 1 else self.CHUNK
            if limit is not None:
                budget = min(budget, limit - vm.icount)
            kind, code, value = vm.run(budget)
            self.blocks = self.instructions = vm.icount
            if kind == winemu.EXIT_BREAKPOINT:
                continue
            if kind == winemu.EXIT_LIMIT:
                pc = vm.pc
                if len(self.threads) > 1 and pc not in self.api_slots and pc not in self._continuations:
                    # time slice used up
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
                # executing data: allowed, as in a process without DEP
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
            # what Windows does without a debugger: a breakpoint exception past the instruction
            self._set_pc(next_pc)
            self.exceptions.dispatch(EXCEPTION_BREAKPOINT, next_pc)
            return
        # other software interrupts are not allowed from user mode
        self.exceptions.dispatch(EXCEPTION_ACCESS_VIOLATION, pc, (0, 0xFFFFFFFF))
