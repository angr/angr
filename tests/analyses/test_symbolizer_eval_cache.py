#!/usr/bin/env python3
# pylint:disable=missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import claripy
from angr.analyses.symbolizer.symbolizer import PropagatorEmulatedEngine
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver
from angr.errors import SimValueError
from angr.state_plugins.solver import SimSolver


class TestSymbolizerEvalCache(unittest.TestCase):
    """_eval_one_cached is keyed by (AST, solver content) and shared across states."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "amd64")
        self.engine = PropagatorEmulatedEngine(project=self.proj)
        self.state = self._fresh_state()
        self.engine.state = self.state
        self.calls = 0

    def _fresh_state(self, plugin=None):
        state = self.proj.factory.blank_state()
        if plugin is None:
            plugin = AndingSimSolver(claripy.SolverReplacement(auto_replace=False))
        state.register_plugin("partial_symbolic_constraint_solver", plugin)
        return state

    def _count(self, state):
        solver = state.partial_symbolic_constraint_solver
        orig = solver.eval_one

        def counting(e, *args, **kwargs):
            self.calls += 1
            return orig(e, *args, **kwargs)

        solver.eval_one = counting
        return solver

    def test_hit_across_states_with_the_same_content(self):
        x = claripy.BVS("x", 64)
        solver = self._count(self.state)
        solver.add(x == 5)
        assert self.engine._eval_one_cached(x) == 5
        assert self.engine._eval_one_cached(x) == 5
        assert self.calls == 1
        # a copy has the same constraints and replacements: served from the cache
        other = self.state.copy()
        self._count(other)
        self.engine.state = other
        assert self.engine._eval_one_cached(x) == 5
        assert self.calls == 1
        assert self.engine._eval_cache_hits == 2 and self.engine._eval_cache_misses == 1

    def test_constraint_and_replacement_changes_miss(self):
        x = claripy.BVS("x", 64)
        y = claripy.BVS("y", 64)
        solver = self._count(self.state)
        solver.add(claripy.Or(x == 5, x == 6))
        with self.assertRaises(SimValueError):
            self.engine._eval_one_cached(x)
        with self.assertRaises(SimValueError):  # the failure is cached too
            self.engine._eval_one_cached(x)
        assert self.calls == 1
        solver.add(x != 6)
        assert self.engine._eval_one_cached(x) == 5
        assert self.calls == 2
        # a new replacement, an overwritten one (same count) and a restored one
        solver._solver.add_replacement(y, claripy.BVV(1, 64))
        assert self.engine._eval_one_cached(x + y) == 6
        assert self.calls == 3
        solver._solver.add_replacement(y, claripy.BVV(2, 64))
        assert self.engine._eval_one_cached(x + y) == 7
        assert self.calls == 4
        solver._solver.add_replacement(y, claripy.BVV(1, 64))
        assert self.engine._eval_one_cached(x + y) == 6
        assert self.calls == 4

    def test_solvers_without_signature_and_disabled_cache_bypass(self):
        x = claripy.BVS("x", 64)
        plain = self._fresh_state(SimSolver())
        solver = self._count(plain)
        solver.add(x == 3)
        self.engine.state = plain
        assert solver.query_signature() is None
        assert self.engine._eval_one_cached(x) == 3
        assert self.engine._eval_one_cached(x) == 3
        assert self.calls == 2
        assert self.engine._eval_cache_hits == 0

        self.engine.state = self.state
        solver = self._count(self.state)
        solver.add(x == 3)
        self.proj.symbolizer_cache_evals = False
        assert self.engine._eval_one_cached(x) == 3
        assert self.engine._eval_one_cached(x) == 3
        assert self.calls == 4

    def test_query_signature_tracks_solver_content(self):
        x = claripy.BVS("x", 64)
        a = SimSolver(claripy.SolverReplacement(auto_replace=False))
        b = SimSolver(claripy.SolverReplacement(auto_replace=False))
        assert a.query_signature() == b.query_signature()
        a._solver.add(x == 1)
        assert a.query_signature() != b.query_signature()
        b._solver.add(x == 1)
        assert a.query_signature() == b.query_signature()
        a._solver.add_replacement(x, claripy.BVV(1, 64))
        assert a.query_signature() != b.query_signature()
        b._solver.add_replacement(x, claripy.BVV(1, 64))
        assert a.query_signature() == b.query_signature()


if __name__ == "__main__":
    unittest.main()
