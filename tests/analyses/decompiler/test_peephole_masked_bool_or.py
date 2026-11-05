#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import BinaryOp, Const, Convert, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import MaskedBoolOrCmpZero

from .ail_equivalence import equivalent


class TestMaskedBoolOrCmpZero(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = MaskedBoolOrCmpZero(self.proj, self.proj.kb, self.m)
        self.x = Register(self.m.next_atom(), 16, 64)

    def _c(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _bin(self, op, a, b, bits=None, signed=False):
        return BinaryOp(self.m.next_atom(), op, [a, b], signed, bits=bits or a.bits)

    def _flag(self, cond, value):
        return self._bin("Mul", Convert(self.m.next_atom(), 1, 64, False, cond), self._c(value))

    def _word(self):
        # SF-like bit 0, ZF at bit 6, a bit-11 term of unrelated value outside the mask
        sf = self._bin("CmpLT", UnaryOp(self.m.next_atom(), "BitwiseNeg", self.x, bits=64), self._c(0), 1, True)
        zf = self._bin("CmpEQ", self.x, self._c(0), 1)
        other = self._bin("And", Register(self.m.next_atom(), 24, 64), self._c(0x800))
        return self._bin("Or", self._bin("Or", self._flag(sf, 1), self._flag(zf, 64)), other)

    def test_masked_word_ne_zero(self):
        expr = self._bin("CmpNE", self._bin("And", self._word(), self._c(65)), self._c(0), 1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "LogicalOr"
        assert equivalent(expr, out)

    def test_masked_word_eq_zero(self):
        expr = self._bin("CmpEQ", self._bin("And", self._word(), self._c(65)), self._c(0), 1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "LogicalAnd"
        assert equivalent(expr, out)

    def test_one_selected_bit(self):
        expr = self._bin("CmpNE", self._bin("And", self._word(), self._c(64)), self._c(0), 1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "CmpEQ"
        assert equivalent(expr, out)

    def test_mask_overlapping_an_unknown_term_stays(self):
        expr = self._bin("CmpNE", self._bin("And", self._word(), self._c(0x841)), self._c(0), 1)
        assert self.opt.optimize(expr) is None


if __name__ == "__main__":
    unittest.main()
