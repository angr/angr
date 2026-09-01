#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import claripy

import angr
from angr.ailment.expression import BinaryOp, Const, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, RemoveRedundantNegations


class TestRemoveRedundantNegations(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.manager = Manager()
        self.opt = RemoveRedundantNegations(self.proj, self.proj.kb, self.manager)

    def _neg(self, inner):
        return UnaryOp(self.manager.next_atom(), "BitwiseNeg", inner)

    def _reg(self, offset):
        return Register(self.manager.next_atom(), offset, 64)

    def _binop(self, op, a, b):
        return BinaryOp(self.manager.next_atom(), op, [a, b], False, bits=64)

    def test_registered(self):
        assert RemoveRedundantNegations in EXPR_OPTS

    def test_folds_neg_of_neg_minus_const(self):
        # ~(~x - 1)  ==>  x + 1
        x = self._reg(16)
        expr = self._neg(self._binop("Sub", self._neg(x), Const(self.manager.next_atom(), 1, 64)))
        out = self.opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "Add"
        assert out.operands[0].likes(x)
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 1

    def test_folds_a_symbolic_subtrahend_too(self):
        # ~(~x - y)  ==>  x + y, for any y
        x, y = self._reg(16), self._reg(24)
        expr = self._neg(self._binop("Sub", self._neg(x), y))
        out = self.opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "Add"
        assert out.operands[0].likes(x) and out.operands[1].likes(y)

    def test_the_sign_matches_the_shape(self):
        # The Add form goes the other way: ~(C + ~x) ==> x - C. Guards against transcribing the
        # mirror rule with the wrong sign.
        x = self._reg(16)
        expr = self._neg(self._binop("Add", Const(self.manager.next_atom(), 1, 64), self._neg(x)))
        out = self.opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "Sub"

    def test_leaves_a_plain_subtraction_alone(self):
        # ~(x - y) is not x + y; without the inner negation there is nothing to fold.
        x, y = self._reg(16), self._reg(24)
        assert self.opt.optimize(self._neg(self._binop("Sub", x, y))) is None

    def test_both_rules_are_equivalent_under_smt(self):
        for bits in (8, 32, 64):
            x, y = claripy.BVS("x", bits), claripy.BVS("y", bits)
            for lhs, rhs in ((~((~x) - y), x + y), (~(y + (~x)), x - y)):
                solver = claripy.Solver()
                solver.add(lhs != rhs)
                assert not solver.satisfiable(), f"{bits}-bit rewrite is not an identity"


if __name__ == "__main__":
    unittest.main()
