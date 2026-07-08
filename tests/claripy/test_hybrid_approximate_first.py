from __future__ import annotations

import pickle
import unittest

from angr import claripy


class TestHybridApproximateFirst(unittest.TestCase):
    def test_kwarg_accepted(self):
        """SolverHybrid accepts approximate_first (default False)."""
        self.assertIsInstance(claripy.SolverHybrid(), claripy.Solver)
        self.assertIsInstance(claripy.SolverHybrid(approximate_first=True), claripy.Solver)

    def test_exact_by_default(self):
        """Without approximate_first, eval results are exact."""
        s = claripy.SolverHybrid()
        x = claripy.BVS("x", 8)
        s.add(claripy.UGT(x, claripy.BVV(253, 8)))
        self.assertEqual(sorted(s.eval(x, 10)), [254, 255])

    def test_approximate_first_eval(self):
        """approximate_first eval answers multi-solution queries.

        Like claripy, the results come from the approximate backend when the
        exact backend cannot narrow them further, so they may be imprecise --
        only the count is guaranteed.
        """
        s = claripy.SolverHybrid(approximate_first=True)
        x = claripy.BVS("x", 8)
        s.add(claripy.UGT(x, claripy.BVV(250, 8)))
        vals = s.eval(x, 4)
        self.assertEqual(len(vals), 4)

    def test_approximate_first_exhaustive(self):
        """When the approximation is exhaustive, its solutions are used."""
        s = claripy.SolverHybrid(approximate_first=True)
        x = claripy.BVS("x", 8)
        s.add(claripy.UGT(x, claripy.BVV(252, 8)))
        self.assertEqual(sorted(s.eval(x, 10)), [253, 254, 255])

    def test_small_n_stays_exact(self):
        """n <= 2 does not trigger the approximate-first path."""
        s = claripy.SolverHybrid(approximate_first=True)
        x = claripy.BVS("x", 8)
        s.add(x == claripy.BVV(7, 8))
        self.assertEqual(list(s.eval(x, 1)), [7])

    def test_pickle_roundtrip(self):
        """approximate_first survives a pickle round-trip."""
        s = claripy.SolverHybrid(approximate_first=True)
        x = claripy.BVS("x", 8)
        s.add(claripy.UGT(x, claripy.BVV(250, 8)))
        s2 = pickle.loads(pickle.dumps(s))
        vals = s2.eval(x, 4)
        self.assertEqual(len(vals), 4)


if __name__ == "__main__":
    unittest.main()
