#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import functools
import struct
import unittest

from angr.analyses.unpacker.emulation.icicle_environment import patched_processors
from angr.rustylib import winemu
from angr.rustylib.winemu import WinVm

from . import icicle_op_vectors as vectors
from .icicle_op_vectors import CODE, DATA, DSIZE, P_OFF, Q_OFF

GPR64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
GPR32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
State = tuple[list[int], int, list[int], bytes]


@functools.cache
def _vm(is_64bit: bool, jit: bool) -> WinVm:
    vm = WinVm(is_64bit, patched_processors(), jit)
    # compile on first use, so that the JIT's path to the helpers is the one tested
    vm.jit_threshold = 0
    vm.mem_map(CODE, 0x1000, 7)
    vm.mem_map(DATA, DSIZE, 3)
    return vm


def _execute(vm: WinVm, code: bytes, state: State) -> State:
    names = GPR64 if vm.is_64bit else GPR32
    gpr, flags, xmm, mem = state
    vm.mem_write(CODE, code + b"\xcc")
    vm.mem_write(DATA, mem)
    for name, value in zip(names, gpr):
        vm.reg_write(name, value)
    for i, value in enumerate(xmm):
        vm.reg_write_bytes(f"xmm{i}", value.to_bytes(16, "little"))
    vm.reg_write("mxcsr", 0x1F80)
    vm.reg_write("eflags", flags | 2)
    vm.pc = CODE
    kind, fault, _ = vm.run(100)
    assert (kind, fault, vm.pc) == (winemu.EXIT_EXCEPTION, winemu.FAULT_SYSCALL, CODE + len(code)), code.hex()
    return (
        [vm.reg_read(name) for name in names],
        vm.reg_read("eflags"),
        [int.from_bytes(vm.reg_read_bytes(f"xmm{i}"), "little") for i in range(len(xmm))],
        vm.mem_read(DATA, DSIZE),
    )


def _run(code: str, is_64bit: bool = False, jit: bool = False, **regs: int) -> WinVm:
    """
    Run hex code with the data pointers in esi / edi and the given registers.
    """
    vm = _vm(is_64bit, jit)
    gpr, _, xmm, _ = vectors.make_state(code, is_64bit, "i")
    raw = bytes.fromhex(code)
    vm.mem_write(CODE, raw + b"\xcc")
    vm.mem_write(DATA, bytes(DSIZE))
    for name, value in zip(GPR64 if is_64bit else GPR32, gpr):
        vm.reg_write(name, value)
    for i, value in enumerate(xmm):
        vm.reg_write_bytes(f"xmm{i}", value.to_bytes(16, "little"))
    for name, value in regs.items():
        vm.reg_write(name, value)
    vm.pc = CODE
    assert vm.run(100)[:2] == (winemu.EXIT_EXCEPTION, winemu.FAULT_SYSCALL), code
    assert vm.pc == CODE + len(raw), code
    return vm


class TestOpVectors(unittest.TestCase):
    """
    The interpreter and the JIT against results recorded from a CPU.
    """

    def _check(self, entries: tuple[tuple, ...]) -> None:
        for is_64bit, code, kind, expected, *mask in entries:
            states = [vectors.make_state(f"{code}/{trial}", bool(is_64bit), kind) for trial in range(4)]
            for jit in (False, True):
                vm = _vm(bool(is_64bit), jit)
                results = [_execute(vm, bytes.fromhex(code), state) for state in states]
                assert vectors.digest(results, mask[0] if mask else 0x8D5) == expected, (code, is_64bit, jit)

    def test_sse2(self):
        self._check(vectors.SSE2)

    def test_ssse3(self):
        self._check(vectors.SSSE3)

    def test_sse41(self):
        self._check(vectors.SSE41)

    def test_sse42(self):
        self._check(vectors.SSE42)

    def test_crypto(self):
        self._check(vectors.CRYPTO)

    def test_x87(self):
        self._check(vectors.X87)

    def test_bmi(self):
        self._check(vectors.BMI)

    def test_bit_scans(self):
        self._check(vectors.BITSCAN)

    def test_multiply_flags(self):
        self._check(vectors.MULTIPLY)


class TestSse(unittest.TestCase):
    def test_conversion_out_of_range(self):
        # cvttsd2si eax, xmm1 / cvtsd2si / cvttss2si of 1e10, NaN and -1e10 give the integer indefinite
        for jit in (False, True):
            for value in (1e10, float("nan"), -1e10):
                vm = _vm(False, jit)
                for code, raw in (("f20f2cc1", struct.pack("<d", value)), ("f20f2dc1", struct.pack("<d", value)),
                                  ("f30f2cc1", struct.pack("<f", value))):  # fmt: skip
                    vm.reg_write_bytes("xmm1", raw.ljust(16, b"\0"))
                    vm.mem_write(CODE, bytes.fromhex(code) + b"\xcc")
                    vm.pc = CODE
                    vm.run(10)
                    assert vm.reg_read("eax") == 0x80000000, (code, value, jit)
        # cvtsd2si rounds to nearest even: 2.5 -> 2, 3.5 -> 4
        for value, expected in ((2.5, 2), (3.5, 4), (-2.5, 0xFFFFFFFE)):
            vm = _vm(False, False)
            vm.reg_write_bytes("xmm1", struct.pack("<d", value).ljust(16, b"\0"))
            vm.mem_write(CODE, bytes.fromhex("f20f2dc1cc"))
            vm.pc = CODE
            vm.run(10)
            assert vm.reg_read("eax") == expected

    def test_string_compare_flags_in_jit(self):
        # sub eax, eax sets flags the JIT keeps in registers; pcmpistri's helper must still win
        vm = _vm(False, True)
        vm.reg_write_bytes("xmm0", b"ab".ljust(16, b"\0"))
        vm.reg_write_bytes("xmm1", b"xxbxxxxxxxxxxxxx")
        vm.mem_write(CODE, bytes.fromhex("29c0 660f3a63c100 cc"))
        vm.pc = CODE
        vm.run(10)
        # equal any: index 2; CF (match), SF (xmm0 ends early), not ZF
        assert (vm.reg_read("ecx"), vm.reg_read("eflags") & 0x8C1) == (2, 0x81)


class TestProcessorState(unittest.TestCase):
    def test_fxsave_fxrstor(self):
        # fninit; fld1; fxsave [edi]; pxor xmm1, xmm1; fstp st(0); fxrstor [edi]; fstp qword [edi + 0x300]
        vm = _run("dbe3 d9e8 0fae07 660fefc9 ddd8 0fae0f dd9f00030000")
        image = vm.mem_read(DATA + Q_OFF, 512)
        assert image[:2] == b"\x7f\x03" and image[24:28] == b"\x80\x1f\0\0"
        # ST0 = 1.0 as an 80-bit value; xmm1 in its slot
        assert image[32:42] == bytes.fromhex("0000000000000080ff3f")
        expected = vectors.make_state("dbe3 d9e8 0fae07 660fefc9 ddd8 0fae0f dd9f00030000", False, "i")[2][1]
        assert int.from_bytes(image[176:192], "little") == expected
        assert int.from_bytes(vm.reg_read_bytes("xmm1"), "little") == expected
        assert vm.mem_read(DATA + Q_OFF + 0x300, 8) == struct.pack("<d", 1.0)

    def test_xsave(self):
        # xsave [edi] with eax = 3 saves x87 and SSE and says so in the header; xgetbv reports the same states
        vm = _run("0fae27 31c9 0f01d0", eax=3, edx=0)
        assert struct.unpack("<Q", vm.mem_read(DATA + Q_OFF + 512, 8))[0] == 3
        assert (vm.reg_read("eax"), vm.reg_read("edx")) == (3, 0)

    def test_extended_precision_operands(self):
        # fld tbyte [esi]; fstp qword [edi]; fld qword [edi]; fstp tbyte [edi + 16]
        vm = _vm(False, False)
        pi = bytes.fromhex("35c26821a2da0fc90040")
        vm.mem_write(CODE, bytes.fromhex("db2e dd1f dd07 db7f10 cc"))
        vm.mem_write(DATA + P_OFF, pi)
        vm.reg_write("esi", DATA + P_OFF)
        vm.reg_write("edi", DATA + Q_OFF)
        vm.pc = CODE
        vm.run(10)
        assert vm.mem_read(DATA + Q_OFF, 8) == struct.pack("<d", 3.141592653589793)
        # back to 80 bits: the double's 53 significant bits
        assert vm.mem_read(DATA + Q_OFF + 16, 10) == bytes.fromhex("00c06821a2da0fc90040")

    def test_small_instructions(self):
        # rdtscp; clflush [esi]; rdrand eax (CF set); fprem needs no 10-byte integer
        vm = _run("0f01f9 0fae3e 0fc7f0 9c", ecx=5)
        assert vm.reg_read("ecx") == 0
        assert struct.unpack("<I", vm.mem_read(vm.reg_read("esp"), 4))[0] & 0x8D5 == 1
        # fld 3.0; fld 7.5 -> fprem: 1.5
        vm = _vm(False, False)
        vm.mem_write(DATA + P_OFF, struct.pack("<2d", 3.0, 7.5))
        vm.mem_write(CODE, bytes.fromhex("dbe3 dd06 dd4608 d9f8 dd1f ddd8 cc"))
        vm.reg_write("esi", DATA + P_OFF)
        vm.reg_write("edi", DATA + Q_OFF)
        vm.pc = CODE
        vm.run(20)
        assert vm.mem_read(DATA + Q_OFF, 8) == struct.pack("<d", 1.5)


class TestInventory(unittest.TestCase):
    # user ops behind the instruction-set extensions cpuid advertises
    ADVERTISED = [
        "pshufb",
        "palignr",
        "pabsb",
        "phaddw",
        "pmaddubsw",
        "pmulhrsw",
        "psignb",
        "pblendw",
        "pblendvb",
        "blendvps",
        "roundps",
        "roundsd",
        "dpps",
        "pmulld",
        "pmuldq",
        "packusdw",
        "pmovsxbw",
        "pmovzxdq",
        "insertps",
        "extractps",
        "mpsadbw",
        "phminposuw",
        "crc32",
        "pcmpistri",
        "pcmpistrm",
        "pcmpestri",
        "pcmpestrm",
        "aesenc",
        "aesenclast",
        "aesdec",
        "aesdeclast",
        "aesimc",
        "aeskeygenassist",
        "paddusb",
        "psubsw",
        "pavgb",
        "pmulhuw",
        "psadbw",
        "packsswb",
        "pshufw",
        "divps",
        "sqrtpd",
        "maxps",
        "minpd",
        "rcpps",
        "rsqrtss",
        "movmskps",
        "lddqu",
        "maskmovdqu",
        "_fxsave",
        "_fxrstor",
        "xsave",
        "xrstor",
        "xsaveopt",
        "rdtscp",
        "rdrand",
        "rdseed",
        "clflush",
        "fprem",
        "fpatan",
        "log2",
        "to_bcd",
        "from_bcd",
    ]

    def test_user_ops(self):
        for is_64bit in (False, True):
            handled = dict(_vm(is_64bit, False).user_ops())
            # palignr is plain SLEIGH; every other name must have a helper
            missing = [name for name in self.ADVERTISED if name != "palignr" and not handled.get(name)]
            assert not missing, missing

    def test_cpuid_matches_the_implementation(self):
        vm = _run("0fa2", eax=1, ecx=0)
        ecx = vm.reg_read("ecx")
        # SSE3, PCLMULQDQ, SSSE3, CX16, SSE4.1, SSE4.2, MOVBE, POPCNT, AES, XSAVE, OSXSAVE, RDRAND
        for bit in (0, 1, 9, 13, 19, 20, 22, 23, 25, 26, 27, 30):
            assert ecx >> bit & 1, bit
        # no FMA, AVX, F16C; no hypervisor
        for bit in (12, 28, 29, 31):
            assert not ecx >> bit & 1, bit
        vm = _run("0fa2", eax=7, ecx=0)
        ebx = vm.reg_read("ebx")
        # BMI1, BMI2, ADX, RDSEED; no AVX2, MPX, AVX-512, SHA
        assert all(ebx >> bit & 1 for bit in (3, 8, 18, 19))
        assert not any(ebx >> bit & 1 for bit in (5, 14, 16, 29))
        vm = _run("0fa2", eax=0xD, ecx=0)
        assert (vm.reg_read("eax"), vm.reg_read("ebx")) == (3, 576)


class TestBitScans(unittest.TestCase):
    def test_zero_source_keeps_destination(self):
        for jit in (False, True):
            for code in ("0fbcc3", "0fbdc3", "660fbcc3", "660fbdc3", "480fbcc3", "480fbdc3"):
                vm = _run(code, True, jit, rax=0x1122334455667788, rbx=0)
                assert vm.reg_read("rax") == 0x1122334455667788, code
                assert vm.reg_read("ZF") == 1
            # a non-zero source: the index, zero-extended for the 32-bit form
            vm = _run("0fbdc3", True, jit, rax=0x1122334455667788, rbx=0x100)
            assert (vm.reg_read("rax"), vm.reg_read("ZF")) == (8, 0)
            # tzcnt / lzcnt of zero are defined: the operand size, CF set
            vm = _run("f30fbcc3", True, jit, rax=0x1122334455667788, rbx=0)
            assert (vm.reg_read("rax"), vm.reg_read("CF")) == (32, 1)
            vm = _run("f3480fbdc3", True, jit, rax=5, rbx=0)
            assert (vm.reg_read("rax"), vm.reg_read("CF")) == (64, 1)



if __name__ == "__main__":
    unittest.main()
