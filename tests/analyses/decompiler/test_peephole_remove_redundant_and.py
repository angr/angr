#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import BinaryOp, Call, Const, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, RemoveRedundantAnds


class TestRemoveRedundantAnds(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.manager = Manager()
        self.opt = RemoveRedundantAnds(self.proj, self.proj.kb, self.manager)

    def _neg(self, inner):
        return UnaryOp(self.manager.next_atom(), "Not", inner)

    def test_registered(self):
        # It lives in the tree only if it is actually wired into the optimization list; the
        # angr 9.3.4 port dropped it, which is how ~(v) & ~(v) survived into the output.
        assert RemoveRedundantAnds in EXPR_OPTS

    def test_folds_two_identical_negations(self):
        # ~(x) & ~(x)  ==>  ~(x).  The two operands are separate atoms, as they are in real AIL.
        x = Register(self.manager.next_atom(), 16, 64)
        expr = BinaryOp(self.manager.next_atom(), "And", [self._neg(x), self._neg(x)], False, bits=64)
        out = self.opt.optimize(expr)
        assert isinstance(out, UnaryOp) and out.op == "Not"
        assert out.operand.likes(x)

    def test_leaves_differing_operands_alone(self):
        x = Register(self.manager.next_atom(), 16, 64)
        y = Register(self.manager.next_atom(), 24, 64)
        expr = BinaryOp(self.manager.next_atom(), "And", [self._neg(x), self._neg(y)], False, bits=64)
        assert self.opt.optimize(expr) is None

    def test_leaves_a_repeated_call_alone(self):
        # likes() ignores idx, so f() & f() compares equal -- but folding it would drop a call.
        def call():
            return Call(self.manager.next_atom(), "f", args=[], bits=64)

        expr = BinaryOp(self.manager.next_atom(), "And", [call(), call()], False, bits=64)
        assert self.opt.optimize(expr) is None

    def test_leaves_a_call_nested_in_an_operand_alone(self):
        inner = BinaryOp(
            self.manager.next_atom(),
            "Add",
            [Call(self.manager.next_atom(), "f", args=[], bits=64), Const(self.manager.next_atom(), 1, 64)],
            False,
            bits=64,
        )
        expr = BinaryOp(self.manager.next_atom(), "And", [inner, inner], False, bits=64)
        assert self.opt.optimize(expr) is None


if __name__ == "__main__":
    unittest.main()
