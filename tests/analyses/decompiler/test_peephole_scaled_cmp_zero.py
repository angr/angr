#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import BinaryOp, Const, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import ScaledCmpZero

from .ail_equivalence import equivalent


class TestScaledCmpZero(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = ScaledCmpZero(self.proj, self.proj.kb, self.m)
        self.x = Register(self.m.next_atom(), 16, 64)

    def _c(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _bin(self, op, a, b, bits=None):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=bits or a.bits)

    def _flag(self):
        # ~x & 1
        return self._bin("And", UnaryOp(self.m.next_atom(), "BitwiseNeg", self.x, bits=64), self._c(1))

    def test_mul_ne_zero(self):
        expr = self._bin("CmpNE", self._bin("Mul", self._flag(), self._c(8)), self._c(0), 1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "CmpNE" and out.operands[0].op == "And"
        assert equivalent(expr, out)

    def test_shl_eq_zero(self):
        expr = self._bin("CmpEQ", self._bin("Shl", self._flag(), self._c(5, 8)), self._c(0), 1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "CmpEQ"
        assert equivalent(expr, out)

    def test_bits_shifted_out_stays(self):
        # x * 8 == 0 does not imply x == 0
        expr = self._bin("CmpEQ", self._bin("Mul", self.x, self._c(8)), self._c(0), 1)
        assert self.opt.optimize(expr) is None


if __name__ == "__main__":
    unittest.main()
