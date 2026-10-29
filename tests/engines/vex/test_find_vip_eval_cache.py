#!/usr/bin/env python3
# pylint:disable=missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.engines.vex"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import claripy
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver
from angr.state_plugins.solver import SimSolver


class TestFindVipEvalCache(unittest.TestCase):
    """find_vip's eval_upto on register values is cached per (AST, constraints, replacements)."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "amd64")
        self.engine = self.proj.factory.default_engine
        self.engine._vip_eval_cache = {}
        self.state = self.proj.factory.blank_state()
        self.state.register_plugin(
            "partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement(auto_replace=False))
        )
        self.engine.state = self.state
        self.solver = self.state.partial_symbolic_constraint_solver
        self.calls = []
        orig = self.solver.eval_upto

        def counting(e, n, **kwargs):
            self.calls.append(e)
            return orig(e, n, **kwargs)

        self.solver.eval_upto = counting

    def _eval(self, expr):
        return self.engine._vip_eval_upto(expr, 3, self.engine._vip_solver_sig(self.solver))

    def test_repeated_query_is_served_from_cache(self):
        x = claripy.BVS("x", 64)
        self.solver.add(x == 5)
        assert self._eval(x) == [5]
        assert self._eval(x) == [5]
        assert len(self.calls) == 1

    def test_new_constraint_or_replacement_invalidates(self):
        x = claripy.BVS("x", 64)
        self.solver.add(claripy.Or(x == 5, x == 6))
        assert set(self._eval(x)) == {5, 6}
        self.solver.add(x != 6)
        assert self._eval(x) == [5]
        assert len(self.calls) == 2
        y = claripy.BVS("y", 64)
        self.solver._solver.add_replacement(y, claripy.BVV(9, 64))
        assert self._eval(x) == [5]
        assert len(self.calls) == 3
        # overwriting a replacement keeps the count but changes the content
        self.solver._solver.add_replacement(y, claripy.BVV(8, 64))
        assert self._eval(x + y) == [13]
        self.solver._solver.add_replacement(y, claripy.BVV(9, 64))
        assert self._eval(x + y) == [14]
        assert len(self.calls) == 5

    def test_concrete_values_and_plain_solvers_bypass_the_cache(self):
        assert self._eval(claripy.BVV(7, 64)) == [7]
        assert not self.engine._vip_eval_cache
        # a solver without replacement bookkeeping gets no cache
        plain = SimSolver()
        assert self.engine._vip_solver_sig(plain) is None


if __name__ == "__main__":
    unittest.main()
