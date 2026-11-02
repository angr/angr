#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import claripy
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.analyses.symbolizer.symbolizer import PropagatorEmulatedEngine
from angr.errors import SimValueError
from angr.state_plugins.solver import SimSolver

from ..common import bin_location


def _state(proj, *constraints):
    state = proj.factory.blank_state()
    state.register_plugin(
        "partial_symbolic_constraint_solver", SimSolver(claripy.SolverReplacement(auto_replace=False))
    )
    for c in constraints:
        state.partial_symbolic_constraint_solver.add(c)
    return state


class TestSymbolizerEvalCache(unittest.TestCase):
    def test_eval_on_a_given_state(self):
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        eng = PropagatorEmulatedEngine(project=proj)
        x = claripy.BVS("x", 64)
        s1 = _state(proj, x == 5)
        s2 = _state(proj, x == 7)
        assert eng._eval_one_cached(x + 1, state=s1) == 6
        assert eng._eval_one_cached(x + 1, state=s1) == 6
        assert eng._eval_cache_hits == 1
        # another solver content is another key
        assert eng._eval_one_cached(x + 1, state=s2) == 8
        free = _state(proj)
        with self.assertRaises(SimValueError):
            eng._eval_one_cached(x + 1, state=free)
        with self.assertRaises(SimValueError):
            eng._eval_one_cached(x + 1, state=free)
        assert eng._eval_cache_hits == 2

    def test_target_reuses_ip_value_only_for_the_same_query(self):
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        x = claripy.BVS("x", 64)
        st = _state(proj, x == 5)
        solver = st.partial_symbolic_constraint_solver
        sig = solver.query_signature()
        reuse = CFGVMDeobfuscation._eval_target_like_ip
        # a wrong stand-in value shows when it is reused
        assert reuse(solver, x + 1, x + 1, 99, sig) == 99
        assert reuse(solver, x + 2, x + 1, 99, sig) == 7
        assert reuse(solver, x + 1, x + 1, 99, None) == 6
        solver.add(x + 1 == 6)
        assert reuse(solver, x + 1, x + 1, 99, sig) == 6


if __name__ == "__main__":
    unittest.main()
