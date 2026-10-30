#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import claripy
from angr.ailment.expression import BinaryOp, Const, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import SingleBitZeroTest

from .ail_equivalence import equivalent


class TestSingleBitZeroTest(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = SingleBitZeroTest(self.proj, self.proj.kb, self.m)

    def _c(self, v, bits=32):
        return Const(self.m.next_atom(), v, bits)

    def _bin(self, op, a, b, bits=None):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=bits or a.bits)

    def _not(self, a):
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", a, bits=a.bits)

    def _v(self, bits=32):
        return VirtualVariable(self.m.next_atom(), 7, bits, VirtualVariableCategory.STACK, oident=-744)

    def _nonzero_word(self, v, bits=32):
        # v | (v + 0x7f..f)
        return self._bin("Or", v, self._bin("Add", v, self._c((1 << (bits - 1)) - 1, bits)))

    def test_msb_idiom_is_nonzero(self):
        # exhaustively on 8 bits, by the solver on 32 and 64
        for v in range(256):
            assert ((v | ((v + 0x7F) & 0xFF)) >> 7) == int(v != 0)
        for bits in (32, 64):
            v = claripy.BVS("v", bits)
            w = v | (v + ((1 << (bits - 1)) - 1))
            msb = claripy.LShR(w, bits - 1) == 1
            assert not claripy.Solver().satisfiable(extra_constraints=[msb != (v != 0)])

    def _vmp_zf_test(self, v, op="CmpEQ"):
        # VMProtect 3.10: (8 & ~(Concat(0x7fffffff | w, 0x80000000 & ~w) >> 28)) == 0, w = v | (v + 0x7fffffff)
        w = self._nonzero_word(v)
        hi = self._bin("Or", self._c(0x7FFFFFFF), w)
        lo = self._bin("And", self._c(0x80000000), self._not(w))
        cat = self._bin("Concat", hi, lo, bits=64)
        e = self._bin("And", self._c(8, 64), self._not(self._bin("Shr", cat, self._c(28, 8), bits=64)))
        return BinaryOp(self.m.next_atom(), op, [e, self._c(0, 64)], False, bits=1)

    def test_vmp_zero_flag_branch(self):
        for op, expect in (("CmpEQ", "CmpEQ"), ("CmpNE", "CmpNE")):
            expr = self._vmp_zf_test(self._v(), op)
            out = self.opt.optimize(expr)
            assert out is not None and out.op == expect
            assert isinstance(out.operands[0], VirtualVariable) and out.operands[1].value == 0
            assert equivalent(expr, out)

    def test_other_bits_and_shapes_are_left_alone(self):
        v = self._v()
        w = self._nonzero_word(v)
        # bit 30 of w is not the zero test
        e = self._bin("And", self._c(1 << 30), w)
        assert self.opt.optimize(BinaryOp(self.m.next_atom(), "CmpEQ", [e, self._c(0)], False, bits=1)) is None
        # a mask with two bits
        e = self._bin("And", self._c(0x80000001), w)
        assert self.opt.optimize(BinaryOp(self.m.next_atom(), "CmpEQ", [e, self._c(0)], False, bits=1)) is None
        # v | (v + 0x7ffffffe) is not the idiom
        w2 = self._bin("Or", v, self._bin("Add", v, self._c(0x7FFFFFFE)))
        e = self._bin("And", self._c(0x80000000), w2)
        assert self.opt.optimize(BinaryOp(self.m.next_atom(), "CmpEQ", [e, self._c(0)], False, bits=1)) is None
        # the MSB of w through an And with 0 is a constant, not a test
        e = self._bin("And", self._c(0x80000000), self._bin("And", w, self._c(0)))
        assert self.opt.optimize(BinaryOp(self.m.next_atom(), "CmpEQ", [e, self._c(0)], False, bits=1)) is None

    def test_through_conversion_and_shift(self):
        v = self._v()
        w = self._nonzero_word(v)
        e = self._bin(
            "And",
            self._c(1, 64),
            self._bin("Shr", BinaryOp(self.m.next_atom(), "Concat", [self._c(0), w], False, bits=64), self._c(31, 8)),
        )
        expr = BinaryOp(self.m.next_atom(), "CmpNE", [e, self._c(0, 64)], False, bits=1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "CmpNE" and equivalent(expr, out)


if __name__ == "__main__":
    unittest.main()
