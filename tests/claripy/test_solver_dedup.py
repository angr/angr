from __future__ import annotations

import unittest

from angr import claripy


class TestConstraintDedup(unittest.TestCase):
    """add() must not store a constraint that is already held (claripy's ConstraintDeduplicatorMixin)."""

    def test_duplicate_add_is_not_stored(self):
        for make in (claripy.Solver, lambda: claripy.SolverReplacement(auto_replace=False)):
            s = make()
            x = claripy.BVS("x", 32)
            c = x > 5
            self.assertEqual(len(s.add(c)), 1)
            self.assertEqual(s.add(c), [])
            self.assertEqual(s.add([c, c, x < 100]), [x < 100])
            self.assertEqual(len(s.constraints), 2)

    def test_merge_readd_does_not_double(self):
        # a state merge that re-adds the union of both sides' constraint lists
        s = claripy.SolverReplacement(auto_replace=False)
        x = claripy.BVS("x", 32)
        s.add([x > 5, x < 100])
        for _ in range(8):
            merged = s.blank_copy()
            merged.add(list(s.constraints) + list(s.branch().constraints))
            s = merged
        self.assertEqual(len(s.constraints), 2)
        self.assertEqual(sorted(s.eval(x, 200)), list(range(6, 100)))


if __name__ == "__main__":
    unittest.main()
