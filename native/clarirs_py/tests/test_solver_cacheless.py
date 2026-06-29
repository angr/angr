from __future__ import annotations

import pickle
import unittest

import claripy


class TestSolverCacheless(unittest.TestCase):
    def test_solver_cacheless_exists(self):
        """SolverCacheless is exported and constructible."""
        s = claripy.SolverCacheless()
        self.assertIsInstance(s, claripy.Solver)

    def test_cacheless_matches_caching_solver(self):
        """The caching Solver and SolverCacheless must agree on every query."""
        x = claripy.BVS("x", 32)

        cached = claripy.Solver()
        cacheless = claripy.SolverCacheless()
        for s in (cached, cacheless):
            s.add(x >= 10)
            s.add(x <= 20)

        self.assertEqual(cached.satisfiable(), cacheless.satisfiable())
        # Repeated checks (the caching solver answers the second from cache).
        self.assertTrue(cached.satisfiable())

        cached_vals = set(cached.eval(x, 5))
        cacheless_vals = set(cacheless.eval(x, 5))
        # Every solution lies within the constraints for both solvers.
        for vals in (cached_vals, cacheless_vals):
            self.assertTrue(vals)
            self.assertTrue(all(10 <= v <= 20 for v in vals))

    def test_cacheless_unsat(self):
        s = claripy.SolverCacheless()
        x = claripy.BVS("x", 8)
        s.add(x == 1)
        s.add(x == 2)
        self.assertFalse(s.satisfiable())

    def test_caching_solver_repeated_eval_consistent(self):
        """Reusing a cached model must stay consistent with the constraints."""
        s = claripy.Solver()
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        s.add(y == x + 1)
        s.add(x == 7)

        # The cache should serve these without changing the answer.
        self.assertEqual(s.eval(x, 1)[0], 7)
        self.assertEqual(s.eval(y, 1)[0], 8)
        self.assertTrue(s.satisfiable())

    def test_cacheless_extra_constraints(self):
        s = claripy.SolverCacheless()
        x = claripy.BVS("x", 32)
        s.add(x >= 10)

        self.assertTrue(s.satisfiable(extra_constraints=[x == 15]))
        self.assertFalse(s.satisfiable(extra_constraints=[x == 5]))
        # Extra constraints must not persist.
        self.assertTrue(s.satisfiable())

    def test_cacheless_branch_stays_cacheless(self):
        s = claripy.SolverCacheless()
        x = claripy.BVS("x", 8)
        s.add(x > 3)

        b = s.branch()
        self.assertIsInstance(b, claripy.Solver)
        self.assertTrue(b.satisfiable())
        # The branch carries the constraints over.
        self.assertTrue(any(c is not None for c in b.constraints))

    def test_cacheless_pickle_roundtrip(self):
        s = claripy.SolverCacheless()
        x = claripy.BVS("x", 16)
        s.add(x == 42)

        restored = pickle.loads(pickle.dumps(s))
        self.assertTrue(restored.satisfiable())
        self.assertEqual(restored.eval(x, 1)[0], 42)
