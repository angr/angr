from __future__ import annotations

import unittest

from angr import claripy


class TestSimplifyConstruction(unittest.TestCase):
    """AST-building entry points that bind their operation result before
    wrapping it (`chop`, `Concat`) simplify it, so a concrete result is folded
    and interned rather than returned as a raw `Extract`/`Concat`."""

    def test_concat_of_concrete_folds(self):
        c = claripy.Concat(claripy.BVV(0, 32), claripy.BVV(0x1337, 32))
        self.assertEqual(c.op, "BVV")
        self.assertEqual(c.concrete_value, 0x1337)
        # interned: equal to the directly-built constant
        self.assertIs(c, claripy.BVV(0x1337, 64))

    def test_chop_of_concrete_folds(self):
        bytes_ = claripy.BVV(0x41424344, 32).chop(8)
        self.assertEqual([b.op for b in bytes_], ["BVV"] * 4)
        self.assertEqual([b.concrete_value for b in bytes_], [0x41, 0x42, 0x43, 0x44])

    def test_chop_isolates_concrete_from_symbolic(self):
        # The concrete high half must come back concrete even when concatenated
        # with a symbolic low half (the chopped pieces are simplified).
        v = claripy.Concat(claripy.BVV(0xAABBCCDD, 32), claripy.BVS("s", 32))
        hi = v.chop(8)[0]
        self.assertFalse(hi.symbolic)
        self.assertEqual(hi.concrete_value, 0xAA)


class TestAddSubConstantFolding(unittest.TestCase):
    """Folding a constant into a (const - x) operand must keep x negated."""

    def test_const_plus_const_minus_sym(self):
        x = claripy.BVS("x", 32)
        for expr in (claripy.BVV(10, 32) + (claripy.BVV(3, 32) - x), (claripy.BVV(3, 32) - x) + claripy.BVV(10, 32)):
            self.assertEqual(expr.op, "__sub__")
            self.assertIs(expr.args[1], x)
            self.assertEqual(expr.args[0].concrete_value, 13)
            s = claripy.Solver()
            s.add(x == 4)
            self.assertEqual(list(s.eval(expr, 1)), [9])


class TestAddSubTermCancellation(unittest.TestCase):
    """A sum with nested additions and subtractions is rewritten as a whole, so that a term appearing with both
    signs cancels and the result keeps the `(a + b) - c` shape."""

    def test_nested_add_sub_cancels(self):
        c = claripy.BVS("c", 32)
        y = claripy.BVS("y", 32)
        self.assertIs((c + y) - y, c)
        self.assertIs((c + c) - c, c)

        expr = claripy.BVV(5, 32) - (claripy.BVV(7, 32) + y) + y + claripy.BVV(7, 32)
        self.assertEqual(expr.op, "BVV")
        self.assertEqual(expr.concrete_value, 5)

    def test_canonical_shape(self):
        c = claripy.BVS("c", 32)
        y = claripy.BVS("y", 32)
        z = claripy.BVS("z", 32)
        # (c + y + 3) - (y + z + 1) => (c + 2) - z
        expr = (c + y + 3) - (y + z + 1)
        self.assertIs(expr, (c + 2) - z)
        # the folded constant joins the side matching its sign
        self.assertIs((c - 0x21) + 1, c - 0x20)
        # negative terms form a single addition
        self.assertIs((c - y) - z, c - (y + z))
