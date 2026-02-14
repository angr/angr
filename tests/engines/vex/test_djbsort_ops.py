"""Tests for djbsort VEX IR operations: Iop_SliceV128 and Iop_Reverse32sIn64_x2."""

from __future__ import annotations

import unittest

import claripy

from angr import SimState, load_shellcode
from angr.engines import HeavyVEXMixin


class TestDjbsortOps(unittest.TestCase):
    """Tests for Iop_SliceV128 and Iop_Reverse32sIn64_x2 VEX IR operations."""

    def setUp(self):
        p = load_shellcode(b"\xc3", arch="AMD64")
        self.state = SimState(project=p)
        self.engine = HeavyVEXMixin(p)

    def _translate(self, op, args):
        self.engine.state = self.state
        return self.engine._perform_vex_expr_Op(op, args)

    def test_slice_v128_zero_offset(self):
        """SliceV128 with imm=0 returns the low 128 bits of Concat(left, right)."""
        left = claripy.BVV(0xAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB, 128)
        right = claripy.BVV(0xCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD, 128)
        imm = claripy.BVV(0, 8)
        result = self._translate("Iop_SliceV128", (left, right, imm))
        assert result.size() == 128
        # imm=0: Concat(left,right)[127:0] == right
        assert self.state.solver.is_true(result == right)

    def test_slice_v128_full_offset(self):
        """SliceV128 with imm=16 returns the high 128 bits of Concat(left, right)."""
        left = claripy.BVV(0xAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB, 128)
        right = claripy.BVV(0xCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD, 128)
        imm = claripy.BVV(16, 8)
        result = self._translate("Iop_SliceV128", (left, right, imm))
        assert result.size() == 128
        # imm=16: Concat(left,right)[255:128] == left
        assert self.state.solver.is_true(result == left)

    def test_slice_v128_mid_offset(self):
        """SliceV128 with imm=8 returns the middle 128 bits of Concat(left, right)."""
        left = claripy.BVV(0x0102030405060708090A0B0C0D0E0F10, 128)
        right = claripy.BVV(0x1112131415161718191A1B1C1D1E1F20, 128)
        imm = claripy.BVV(8, 8)
        result = self._translate("Iop_SliceV128", (left, right, imm))
        assert result.size() == 128
        # imm=8: Concat(left,right)[191:64]
        # = left[63:0] ++ right[127:64]
        expected = claripy.BVV(0x090A0B0C0D0E0F101112131415161718, 128)
        assert self.state.solver.is_true(result == expected)

    def test_reverse_32s_in_64_x2(self):
        """Reverse32sIn64_x2 swaps 32-bit halves within each 64-bit half."""
        # Input:  [A B C D] where each is 32 bits
        # Layout: arg[127:96]=A, arg[95:64]=B, arg[63:32]=C, arg[31:0]=D
        # Output: [B A D C] = Concat(arg[95:64], arg[127:96], arg[31:0], arg[63:32])
        a = claripy.BVV(0x11111111, 32)
        b = claripy.BVV(0x22222222, 32)
        c = claripy.BVV(0x33333333, 32)
        d = claripy.BVV(0x44444444, 32)
        arg = claripy.Concat(a, b, c, d)
        result = self._translate("Iop_Reverse32sIn64_x2", (arg,))
        assert result.size() == 128
        expected = claripy.Concat(b, a, d, c)
        assert self.state.solver.is_true(result == expected)

    def test_reverse_32s_in_64_x2_concrete(self):
        """Reverse32sIn64_x2 with a concrete 128-bit value."""
        arg = claripy.BVV(0xAABBCCDDEEFF0011_2233445566778899, 128)
        result = self._translate("Iop_Reverse32sIn64_x2", (arg,))
        assert result.size() == 128
        # arg[127:96]=0xAABBCCDD, arg[95:64]=0xEEFF0011
        # arg[63:32]=0x22334455,  arg[31:0]=0x66778899
        # result = Concat(arg[95:64], arg[127:96], arg[31:0], arg[63:32])
        #        = 0xEEFF0011_AABBCCDD_66778899_22334455
        expected = claripy.BVV(0xEEFF0011AABBCCDD6677889922334455, 128)
        assert self.state.solver.is_true(result == expected)


if __name__ == "__main__":
    unittest.main()
