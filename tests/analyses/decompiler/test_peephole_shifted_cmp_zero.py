#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import ShiftedCmpZero

from .ail_equivalence import equivalent


class TestShiftedCmpZero(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = ShiftedCmpZero(self.proj, self.proj.kb, self.m)
        self.x = Register(self.m.next_atom(), 16, 64)

    def _c(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _bin(self, op, a, b, bits=None, signed=False):
        return BinaryOp(self.m.next_atom(), op, [a, b], signed, bits=bits or a.bits)

    def _masked(self, mask=64):
        return self._bin("And", self.x, self._c(mask))

    def test_shr_eq_zero(self):
        expr = self._bin("CmpEQ", self._bin("Shr", self._masked(), self._c(3, 8)), self._c(0), 1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "CmpEQ" and out.operands[0].op == "And"
        assert equivalent(expr, out)

    def test_bound_form(self):
        # (x & 64) <=u 7  ==>  (x & 64) == 0
        expr = self._bin("CmpLE", self._masked(), self._c(7), 1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "CmpEQ"
        assert equivalent(expr, out)
        expr = self._bin("CmpGT", self._masked(), self._c(7), 1)
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "CmpNE"
        assert equivalent(expr, out)

    def test_sar_signed_lt_zero(self):
        expr = self._bin(
            "CmpLT", self._bin("Sar", self._masked(0xFFFFFFFFFFFFFF00), self._c(8, 8)), self._c(0), 1, signed=True
        )
        out = self.opt.optimize(expr)
        assert out is not None and out.op == "CmpLT" and out.signed
        assert equivalent(expr, out)

    def test_unknown_low_bits_stay(self):
        expr = self._bin("CmpEQ", self._bin("Shr", self._masked(0x44), self._c(3, 8)), self._c(0), 1)
        assert self.opt.optimize(expr) is None
        assert self.opt.optimize(self._bin("CmpLE", self._masked(0x44), self._c(7), 1)) is None

    def test_signed_compare_of_logical_shift_stays(self):
        expr = self._bin(
            "CmpLT", self._bin("Shr", self._masked(0xFFFFFFFFFFFFFF00), self._c(8, 8)), self._c(0), 1, signed=True
        )
        assert self.opt.optimize(expr) is None


if __name__ == "__main__":
    unittest.main()
