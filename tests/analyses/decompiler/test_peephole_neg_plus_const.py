#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import claripy

import angr
from angr.ailment.expression import BinaryOp, Const, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, NegPlusConstToSub

BITS = 64


class TestNegPlusConstToSub(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.manager = Manager(arch=None)
        self.opt = NegPlusConstToSub(self.proj, self.proj.kb, self.manager)
        self.x = Register(self.manager.next_atom(), 16, BITS)

    def _c(self, value):
        return Const(self.manager.next_atom(), value, BITS)

    def _bin(self, op, a, b):
        return BinaryOp(self.manager.next_atom(), op, [a, b], False, bits=BITS)

    def _un(self, op, a):
        return UnaryOp(self.manager.next_atom(), op, a)

    def test_registered(self):
        assert NegPlusConstToSub in EXPR_OPTS

    def test_folds_the_forms_the_vm_emits(self):
        cases = [
            (self._bin("Add", self._un("Neg", self.x), self._c(64)), 64),
            (self._bin("Add", self._un("Neg", self._bin("Sub", self.x, self._c(99))), self._c(64)), 163),
            (self._bin("Add", self._un("BitwiseNeg", self.x), self._c(64)), 63),
            (self._bin("Add", self._c(64), self._un("Neg", self.x)), 64),
            (self._bin("Add", self._un("BitwiseNeg", self._bin("Sub", self.x, self._c(99))), self._c(64)), 162),
            (self._bin("Add", self._un("Neg", self._bin("Add", self.x, self._c(7))), self._c(64)), 57),
        ]
        for expr, expected in cases:
            out = self.opt.optimize(expr)
            assert out is not None and out.op == "Sub", f"{expr} was not folded"
            assert isinstance(out.operands[0], Const)
            assert out.operands[0].value == expected, f"{expr} -> {out}, expected {expected} - x"
            assert out.operands[1].likes(self.x)

    def test_every_fold_is_an_identity(self):
        """The rewrites must be exact, not merely shorter."""
        x = claripy.BVS("x", BITS)
        for lhs, rhs in (
            (-x + 64, 64 - x),
            (-(x - 99) + 64, 163 - x),
            (~x + 64, 63 - x),
            (~(x - 99) + 64, 162 - x),
            (-(x + 7) + 64, 57 - x),
        ):
            solver = claripy.Solver()
            solver.add(lhs != rhs)
            assert not solver.satisfiable(), "rewrite is not an identity"

    def test_leaves_a_non_constant_addend_alone(self):
        y = Register(self.manager.next_atom(), 24, BITS)
        assert self.opt.optimize(self._bin("Add", self._un("Neg", self.x), y)) is None

    def test_leaves_a_plain_addition_alone(self):
        assert self.opt.optimize(self._bin("Add", self.x, self._c(64))) is None

    def test_result_does_not_refold(self):
        """The output must be a fixed point, or the optimizer would loop on it."""
        folded = self.opt.optimize(self._bin("Add", self._un("Neg", self.x), self._c(64)))
        assert self.opt.optimize(folded) is None


if __name__ == "__main__":
    unittest.main()
