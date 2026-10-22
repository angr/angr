from __future__ import annotations

import itertools
import unittest

from angr.claripy import BVS, BoolS, Solver, is_false, is_true, minimize_boolean


class TestMinimizeBoolean(unittest.TestCase):
    def setUp(self):
        self.x = BoolS("x", explicit_name=True)
        self.y = BoolS("y", explicit_name=True)
        self.z = BoolS("z", explicit_name=True)

    def assert_equivalent(self, a, b):
        s = Solver()
        s.add(a != b)
        self.assertFalse(s.satisfiable())

    def test_merges_minterms(self):
        expr = (~self.x & ~self.y & ~self.z) | (~self.x & ~self.y & self.z)
        self.assertIs(minimize_boolean(expr), ~self.x & ~self.y)

    def test_absorption(self):
        self.assertIs(minimize_boolean(self.x | (self.x & self.y & self.z)), self.x)
        self.assertIs(minimize_boolean((self.x | self.y) & (self.x | ~self.y)), self.x)

    def test_constants(self):
        self.assertTrue(is_true(minimize_boolean(self.x | (~self.x & self.y) | ~self.y)))
        self.assertTrue(is_false(minimize_boolean((self.x | self.y) & ~self.x & ~self.y)))
        self.assertIs(minimize_boolean(self.x), self.x)

    def test_unifies_comparisons(self):
        a = BVS("a", 32)
        b = BVS("b", 32)
        self.assertTrue(is_true(minimize_boolean(a.UGT(b) | a.ULE(b))))
        self.assertTrue(is_true(minimize_boolean(a.SGE(b) | a.SLT(b))))
        expr = ((a != b) & a.UGT(b)) | ((a == b) & a.UGT(b))
        self.assertIs(minimize_boolean(expr), a.UGT(b))

    def test_predicate_limit(self):
        expr = self.x | (self.x & self.y & self.z)
        self.assertIs(minimize_boolean(expr, max_predicates=3), self.x)
        self.assertIs(minimize_boolean(expr, max_predicates=2), expr)

    def test_preserves_meaning(self):
        literals = [self.x, self.y, self.z, ~self.x, ~self.y, ~self.z]
        for a, b, c in itertools.combinations(literals, 3):
            for expr in ((a & b) | (b & c) | (a & c), (a | b) & (~b | c)):
                self.assert_equivalent(minimize_boolean(expr), expr)

    def test_rejects_non_bool(self):
        with self.assertRaises(TypeError):
            minimize_boolean(BVS("a", 32))


if __name__ == "__main__":
    unittest.main()
