# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest

import angr
from angr import claripy
from angr.engines.vex.claripy import irop
from angr.errors import UnsupportedIROpError


def calc(op, *args):
    """Evaluate a SimIROp on concrete arguments, returning a Python int."""
    simop = irop.operations[op]
    assert simop._calculate is not None  # pylint:disable=protected-access
    result = simop._calculate([claripy.BVV(value, width) for value, width in args])  # pylint:disable=protected-access
    value = result.concrete_value
    assert isinstance(value, int)
    return value


def pack(values, elem_bits):
    """Little-endian lane packing: values[0] is the least significant lane."""
    out = 0
    mask = (1 << elem_bits) - 1
    for i, v in enumerate(values):
        out |= (v & mask) << (elem_bits * i)
    return out


def unpack(value, elem_bits, count):
    mask = (1 << elem_bits) - 1
    return [(value >> (elem_bits * i)) & mask for i in range(count)]


def run_insn(code, setup=None, arch="AMD64"):
    """Execute a single instruction from `code` and return the successor state."""
    proj = angr.load_shellcode(code, arch=arch)
    state = proj.factory.blank_state(addr=0)
    if setup is not None:
        setup(state)
    return proj.factory.successors(state, num_inst=1).successors[0]


class TestAVX512Ops(unittest.TestCase):
    """Symbolic implementations of the EVEX operations, against oracles."""

    def test_expand_bits_to_vector(self):
        # width code 2 -> 32-bit elements
        got = calc("Iop_ExpandBitsToV512", (0b1011, 64), (2, 8))
        assert unpack(got, 32, 16) == [0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF] + [0] * 12

        # width code 3 -> 64-bit elements
        got = calc("Iop_ExpandBitsToV512", (0b10000001, 64), (3, 8))
        assert unpack(got, 64, 8) == [0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0xFFFFFFFFFFFFFFFF]

        # and the narrower vector widths
        assert unpack(calc("Iop_ExpandBitsToV256", (0b0101, 64), (2, 8)), 32, 8) == [
            0xFFFFFFFF,
            0,
            0xFFFFFFFF,
            0,
            0,
            0,
            0,
            0,
        ]
        assert unpack(calc("Iop_ExpandBitsToV128", (0b11, 64), (3, 8)), 64, 2) == [
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ]

    def test_ternlog_truth_table(self):
        a, b, c = 0b1010, 0b1100, 0b0011
        for imm8 in (0x00, 0xFF, 0xCA, 0x1E, 0x96, 0xE2):
            got = calc("Iop_Ternlog32x16", (a, 512), (b, 512), (c, 512), (imm8, 8)) & 0xF
            expected = 0
            for bit in range(4):
                index = (((a >> bit) & 1) << 2) | (((b >> bit) & 1) << 1) | ((c >> bit) & 1)
                expected |= ((imm8 >> index) & 1) << bit
            assert got == expected, f"imm8={imm8:#x}"

    def test_ternlog_identities(self):
        a, b, c = 0xF0F0, 0xFF00, 0x00FF
        # the truth tables that select a single input, and the basic logic ones
        assert calc("Iop_Ternlog32x16", (a, 512), (b, 512), (c, 512), (0xF0, 8)) & 0xFFFF == a
        assert calc("Iop_Ternlog32x16", (a, 512), (b, 512), (c, 512), (0xCC, 8)) & 0xFFFF == b
        assert calc("Iop_Ternlog32x16", (a, 512), (b, 512), (c, 512), (0xAA, 8)) & 0xFFFF == c
        assert calc("Iop_Ternlog32x16", (a, 512), (b, 512), (c, 512), (0x80, 8)) & 0xFFFF == a & b & c
        assert calc("Iop_Ternlog32x16", (a, 512), (b, 512), (c, 512), (0xFE, 8)) & 0xFFFF == a | b | c

    def test_mask_compare_predicates(self):
        src1 = pack(list(range(16)), 32)
        src2 = pack([7] * 16, 32)
        all_ones = (1 << 16) - 1
        expected = {
            0: lambda i: i == 7,  # EQ
            1: lambda i: i < 7,  # LT
            2: lambda i: i <= 7,  # LE
            3: lambda i: False,  # FALSE
            4: lambda i: i != 7,  # NEQ
            5: lambda i: i >= 7,  # GE (NLT)
            6: lambda i: i > 7,  # GT (NLE)
            7: lambda i: True,  # TRUE
        }
        for pred, want in expected.items():
            got = calc("Iop_Cmp32Sx16", (0, 64), (src1, 512), (src2, 512), (pred, 8))
            assert got == sum(1 << i for i in range(16) if want(i)), f"predicate {pred}"

        # the destination argument is not a writemask: it must not filter
        got_zero_dst = calc("Iop_Cmp32Sx16", (0, 64), (src1, 512), (src2, 512), (1, 8))
        got_full_dst = calc("Iop_Cmp32Sx16", (all_ones, 64), (src1, 512), (src2, 512), (1, 8))
        assert got_zero_dst == got_full_dst

    def test_mask_compare_signedness(self):
        # -1 is below 0 signed, but above it unsigned
        src1 = pack([0xFFFFFFFF] * 16, 32)
        src2 = pack([0] * 16, 32)
        assert calc("Iop_Cmp32Sx16", (0, 64), (src1, 512), (src2, 512), (1, 8)) == 0xFFFF  # signed LT
        assert calc("Iop_Cmp32Ux16", (0, 64), (src1, 512), (src2, 512), (1, 8)) == 0  # unsigned LT

    def test_mask_test(self):
        src1 = pack([i % 2 for i in range(16)], 32)
        src2 = pack([1] * 16, 32)
        odd_lanes = sum(1 << i for i in range(16) if i % 2 == 1)
        assert calc("Iop_Test32x16", (0, 64), (src1, 512), (src2, 512)) == odd_lanes
        assert calc("Iop_TestN32x16", (0, 64), (src1, 512), (src2, 512)) == (~odd_lanes) & 0xFFFF

    def test_permute(self):
        values = [100 + i for i in range(16)]
        # reverse
        got = calc("Iop_Perm32x16", (pack(list(reversed(range(16))), 32), 512), (pack(values, 32), 512))
        assert unpack(got, 32, 16) == list(reversed(values))
        # broadcast lane 3
        got = calc("Iop_Perm32x16", (pack([3] * 16, 32), 512), (pack(values, 32), 512))
        assert unpack(got, 32, 16) == [values[3]] * 16
        # the index is taken modulo the lane count
        got = calc("Iop_Perm32x16", (pack([16 + 5] * 16, 32), 512), (pack(values, 32), 512))
        assert unpack(got, 32, 16) == [values[5]] * 16

    def test_zmm_slices(self):
        lanes = [i + 1 for i in range(8)]
        packed = pack(lanes, 64)
        for i in range(8):
            assert calc(f"Iop_V512to64_{i}", (packed, 512)) == lanes[i]
        assert calc("Iop_V512toV256_0", (packed, 512)) == pack(lanes[:4], 64)
        assert calc("Iop_V512toV256_1", (packed, 512)) == pack(lanes[4:], 64)
        assert calc("Iop_V256HLtoV512", (pack(lanes[4:], 64), 256), (pack(lanes[:4], 64), 256)) == packed

    def test_bitwise_v512(self):
        a, b = 0xF0F0, 0x00FF
        assert calc("Iop_AndV512", (a, 512), (b, 512)) == a & b
        assert calc("Iop_OrV512", (a, 512), (b, 512)) == a | b
        assert calc("Iop_NotV512", (a, 512)) == ((1 << 512) - 1) ^ a

    def test_deliberately_unsupported_ops(self):
        """Ops we refuse rather than implement incorrectly."""
        for op in ("Iop_Cmp32Fx16", "Iop_Cmp64Fx8", "Iop_PermI32x16", "Iop_PermI8x64"):
            with self.assertRaises(UnsupportedIROpError):
                irop.vexop_to_simop(op)


class TestAVX512Execution(unittest.TestCase):
    """Real AVX-512 machine code, executed concretely through angr."""

    def test_vpaddd_unmasked(self):
        # vpaddd %zmm2, %zmm1, %zmm0
        def setup(state):
            state.registers.store("zmm1", claripy.BVV(pack(list(range(16)), 32), 512))
            state.registers.store("zmm2", claripy.BVV(pack([100] * 16, 32), 512))

        state = run_insn(bytes.fromhex("62f17548fec2"), setup)
        got = state.solver.eval(state.registers.load("zmm0"))
        assert unpack(got, 32, 16) == [i + 100 for i in range(16)]

    def _masked_setup(self, state):
        state.registers.store("zmm0", claripy.BVV(pack([0xDEAD] * 16, 32), 512))
        state.registers.store("zmm1", claripy.BVV(pack(list(range(16)), 32), 512))
        state.registers.store("zmm2", claripy.BVV(pack([100] * 16, 32), 512))
        state.registers.store("k1", claripy.BVV(0b1010, 64))

    def test_vpaddd_merge_masking(self):
        # vpaddd %zmm2, %zmm1, %zmm0{%k1}: unselected lanes keep the old zmm0
        state = run_insn(bytes.fromhex("62f17549fec2"), self._masked_setup)
        got = state.solver.eval(state.registers.load("zmm0"))
        assert unpack(got, 32, 16) == [(i + 100) if (0b1010 >> i) & 1 else 0xDEAD for i in range(16)]

    def test_vpaddd_zero_masking(self):
        # vpaddd %zmm2, %zmm1, %zmm0{%k1}{z}: unselected lanes are zeroed
        state = run_insn(bytes.fromhex("62f175c9fec2"), self._masked_setup)
        got = state.solver.eval(state.registers.load("zmm0"))
        assert unpack(got, 32, 16) == [(i + 100) if (0b1010 >> i) & 1 else 0 for i in range(16)]

    def test_vaddps_float(self):
        # vaddps %zmm2, %zmm1, %zmm0
        def setup(state):
            state.registers.store("zmm1", claripy.BVV(pack([0x3F800000] * 16, 32), 512))  # 1.0f
            state.registers.store("zmm2", claripy.BVV(pack([0x40000000] * 16, 32), 512))  # 2.0f

        state = run_insn(bytes.fromhex("62f1744858c2"), setup)
        got = state.solver.eval(state.registers.load("zmm0"))
        assert unpack(got, 32, 16) == [0x40400000] * 16  # 3.0f

    def test_vpcmpgtd_into_opmask(self):
        # vpcmpgtd %zmm2, %zmm1, %k2
        def setup(state):
            state.registers.store("zmm1", claripy.BVV(pack(list(range(16)), 32), 512))
            state.registers.store("zmm2", claripy.BVV(pack([7] * 16, 32), 512))

        state = run_insn(bytes.fromhex("62f1754866d2"), setup)
        assert state.solver.eval(state.registers.load("k2")) == sum(1 << i for i in range(16) if i > 7)

    def test_vpcmpgtd_with_writemask(self):
        # vpcmpgtd %zmm2, %zmm1, %k2{%k3}
        def setup(state):
            state.registers.store("zmm1", claripy.BVV(pack(list(range(16)), 32), 512))
            state.registers.store("zmm2", claripy.BVV(pack([7] * 16, 32), 512))
            state.registers.store("k3", claripy.BVV(0b1111000011110000, 64))

        state = run_insn(bytes.fromhex("62f1754b66d2"), setup)
        expected = sum(1 << i for i in range(16) if i > 7) & 0b1111000011110000
        assert state.solver.eval(state.registers.load("k2")) == expected

    def test_vptestmd(self):
        # vptestmd %zmm2, %zmm1, %k2
        def setup(state):
            state.registers.store("zmm1", claripy.BVV(pack([i % 2 for i in range(16)], 32), 512))
            state.registers.store("zmm2", claripy.BVV(pack([1] * 16, 32), 512))

        state = run_insn(bytes.fromhex("62f2754827d2"), setup)
        assert state.solver.eval(state.registers.load("k2")) == sum(1 << i for i in range(16) if i % 2 == 1)

    def test_vpermd(self):
        # vpermd %zmm2, %zmm1, %zmm0 -- zmm1 holds the indices
        def setup(state):
            state.registers.store("zmm1", claripy.BVV(pack(list(reversed(range(16))), 32), 512))
            state.registers.store("zmm2", claripy.BVV(pack([100 + i for i in range(16)], 32), 512))

        state = run_insn(bytes.fromhex("62f2754836c2"), setup)
        got = state.solver.eval(state.registers.load("zmm0"))
        assert unpack(got, 32, 16) == list(reversed([100 + i for i in range(16)]))

    def test_vpternlogd(self):
        # vpternlogd $0xca, %zmm2, %zmm1, %zmm0
        a, b, c = 0xF0F0, 0xFF00, 0x00FF

        def setup(state):
            state.registers.store("zmm0", claripy.BVV(a, 512))
            state.registers.store("zmm1", claripy.BVV(b, 512))
            state.registers.store("zmm2", claripy.BVV(c, 512))

        state = run_insn(bytes.fromhex("62f3754825c2ca"), setup)
        got = state.solver.eval(state.registers.load("zmm0")) & 0xFFFF
        expected = 0
        for bit in range(16):
            index = (((a >> bit) & 1) << 2) | (((b >> bit) & 1) << 1) | ((c >> bit) & 1)
            expected |= ((0xCA >> index) & 1) << bit
        assert got == expected

    def test_vpxord_self_zeroes(self):
        # vpxord %zmm4, %zmm4, %zmm4 -- the idiomatic register clear
        def setup(state):
            state.registers.store("zmm4", claripy.BVV((1 << 512) - 1, 512))

        state = run_insn(bytes.fromhex("62f15d48efe4"), setup)
        assert state.solver.eval(state.registers.load("zmm4")) == 0

    def test_vl_forms_zero_the_upper_lanes(self):
        # vpaddd %ymm2, %ymm1, %ymm0 (EVEX.256) must clear bits 511:256
        def setup(state):
            state.registers.store("zmm0", claripy.BVV((1 << 512) - 1, 512))
            state.registers.store("zmm1", claripy.BVV(pack([1] * 16, 32), 512))
            state.registers.store("zmm2", claripy.BVV(pack([2] * 16, 32), 512))

        state = run_insn(bytes.fromhex("62f17528fec2"), setup)
        got = state.solver.eval(state.registers.load("zmm0"))
        assert unpack(got, 32, 16) == [3] * 8 + [0] * 8


class TestAVX512Analyses(unittest.TestCase):
    """AVX-512 code must not break the analyses that run over lifted blocks."""

    CODE = bytes.fromhex(
        "62f17548fec2"  # vpaddd  %zmm2, %zmm1, %zmm0
        "62f1754966d3"  # vpcmpgtd %zmm3, %zmm1, %k2{%k1}
        "62f3754825c2ca"  # vpternlogd $0xca, %zmm2, %zmm1, %zmm0
        "62f2754836c2"  # vpermd  %zmm2, %zmm1, %zmm0
        "c3"  # ret
    )

    def test_cfg_and_decompiler_survive_avx512(self):
        proj = angr.load_shellcode(self.CODE, arch="AMD64", start_offset=0, load_address=0x400000)
        cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=True)
        assert len(cfg.graph.nodes) >= 1

        func = cfg.kb.functions[0x400000]
        # decompilation must produce output rather than raising; unsupported
        # ops are allowed to degrade into dirty expressions
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text

    def test_unsupported_ops_can_be_bypassed(self):
        """BYPASS_UNSUPPORTED_IROP turns a blocked op into a fresh symbol."""
        # vcmpps $0, %zmm2, %zmm1, %k1 uses Iop_Cmp32Fx16, which we do not
        # implement; with the option set, execution continues.
        code = bytes.fromhex("62f17448c2ca00")
        proj = angr.load_shellcode(code, arch="AMD64")
        state = proj.factory.blank_state(addr=0, add_options={angr.options.BYPASS_UNSUPPORTED_IROP})
        succ = proj.factory.successors(state, num_inst=1)
        assert len(succ.successors) == 1


if __name__ == "__main__":
    unittest.main()
