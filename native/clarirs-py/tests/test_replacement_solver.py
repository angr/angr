from __future__ import annotations

import pickle
import unittest

import claripy


class TestReplacementSolver(unittest.TestCase):
    def test_replacement_solver_exists(self):
        """SolverReplacement is exported and constructible."""
        s = claripy.SolverReplacement()
        self.assertIsInstance(s, claripy.Solver)

    def test_auto_replace_default_extracts_replacements(self):
        """By default (auto_replace=True) `x == c` is turned into a replacement."""
        s = claripy.SolverReplacement()
        x = claripy.BVS("x", 8)
        s.add(x == 5)
        self.assertEqual(s.eval(x, 1)[0], 5)

    def test_auto_replace_true_keyword(self):
        """Passing auto_replace=True explicitly behaves like the default."""
        s = claripy.SolverReplacement(auto_replace=True)
        x = claripy.BVS("x", 8)
        s.add(x == 9)
        self.assertEqual(s.eval(x, 1)[0], 9)

    def test_auto_replace_false_disables_extraction(self):
        """With auto_replace=False, adding `x == c` does not register a
        replacement, but explicit replacements still work."""
        s = claripy.SolverReplacement(auto_replace=False)
        x = claripy.BVS("x", 8)
        s.add(x == 5)

        # The backend still solves the constraint, so x evaluates to 5.
        self.assertEqual(s.eval(x, 1)[0], 5)

        # Explicit replacements override the value regardless of auto_replace.
        s.add_replacement(x, claripy.BVV(7, 8))
        self.assertEqual(s.eval(x, 1)[0], 7)

    def test_auto_replace_clear_replacements(self):
        s = claripy.SolverReplacement()
        x = claripy.BVS("x", 8)
        s.add_replacement(x, claripy.BVV(3, 8))
        self.assertEqual(s.eval(x, 1)[0], 3)
        s.clear_replacements()
        # After clearing, x is unconstrained again (any value is allowed).
        self.assertTrue(s.satisfiable())

    def test_auto_replace_branch_preserves_setting(self):
        """branch() clones the solver, keeping auto_replace=False."""
        s = claripy.SolverReplacement(auto_replace=False)
        b = s.branch()
        x = claripy.BVS("x", 8)
        b.add(x == 5)
        b.add_replacement(x, claripy.BVV(4, 8))
        self.assertEqual(b.eval(x, 1)[0], 4)

    def test_auto_replace_pickle_roundtrip(self):
        """auto_replace survives a pickle round-trip."""
        s = claripy.SolverReplacement(auto_replace=False)
        restored = pickle.loads(pickle.dumps(s))
        self.assertIsInstance(restored, claripy.Solver)
        x = claripy.BVS("x", 8)
        restored.add(x == 5)
        restored.add_replacement(x, claripy.BVV(6, 8))
        self.assertEqual(restored.eval(x, 1)[0], 6)
