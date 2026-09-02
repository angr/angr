#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment.expression import BinaryOp, Const, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.mba_simplifier import MBATemplateSimplifier

BITS = 64


class TestMBATemplateSimplifier(unittest.TestCase):
    def setUp(self):
        self.m = Manager(arch=None)
        self.s = MBATemplateSimplifier(ail_manager=self.m)
        self.x = Register(self.m.next_atom(), 16, BITS)
        self.y = Register(self.m.next_atom(), 24, BITS)

    def _c(self, v):
        return Const(self.m.next_atom(), v, BITS)

    def _b(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=BITS)

    def _u(self, op, a):
        return UnaryOp(self.m.next_atom(), op, a)

    def test_recognises_the_classic_identities(self):
        x, y = self.x, self.y
        cases = [
            # (x ^ y) + 2*(x & y)  ==  x + y
            (self._b("Add", self._b("Xor", x, y), self._b("Mul", self._c(2), self._b("And", x, y))), "Add"),
            # (x | y) + (x & y)  ==  x + y
            (self._b("Add", self._b("Or", x, y), self._b("And", x, y)), "Add"),
            # (x | y) - (x & y)  ==  x ^ y
            (self._b("Sub", self._b("Or", x, y), self._b("And", x, y)), "Xor"),
            # x + y - 2*(x & y)  ==  x ^ y
            (self._b("Sub", self._b("Add", x, y), self._b("Mul", self._c(2), self._b("And", x, y))), "Xor"),
            # (x & ~y) | (~x & y)  ==  x ^ y
            (
                self._b(
                    "Or",
                    self._b("And", x, self._u("BitwiseNeg", y)),
                    self._b("And", self._u("BitwiseNeg", x), y),
                ),
                "Xor",
            ),
        ]
        for expr, expected_op in cases:
            out = self.s.simplify(expr)
            assert out is not None, f"{expr} was not recognised"
            assert out.op == expected_op, f"{expr} -> {out}, expected a {expected_op}"

    def test_leaves_a_non_identity_alone(self):
        # x + (x & y) is not any of the templates; it must not be rewritten into one
        expr = self._b("Add", self.x, self._b("And", self.x, self._b("Or", self.x, self.y)))
        assert self.s.simplify(expr) is None

    def test_refuses_expressions_outside_the_mba_fragment(self):
        # a shift is not in the fragment, so the subtree is not analysed at all
        shifted = self._b("Shl", self.x, self._c(3))
        expr = self._b("Add", self._b("Xor", self.x, self.y), shifted)
        assert self.s.simplify(expr) is None

    def test_refuses_mixed_widths(self):
        narrow = Register(self.m.next_atom(), 32, 32)
        expr = BinaryOp(self.m.next_atom(), "Add", [self._b("Xor", self.x, self.y), narrow], False, bits=BITS)
        assert self.s.simplify(expr) is None

    def test_small_expressions_are_left_alone(self):
        # nothing to gain: the template would be no smaller than the expression
        assert self.s.simplify(self._b("Xor", self.x, self.y)) is None

    def test_every_rewrite_is_proved(self):
        """A rewrite only happens after the solver agrees; the counter must reflect that."""
        expr = self._b("Add", self._b("Or", self.x, self.y), self._b("And", self.x, self.y))
        assert self.s.simplify(expr) is not None
        assert self.s.simplified == 1
        assert self.s.verified_away == 0


if __name__ == "__main__":
    unittest.main()
