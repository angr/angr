#!/usr/bin/env python3
# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import unittest

import angr
from angr import claripy
from angr.errors import SimUnsatError, SimValueError
from angr.state_plugins.solver import SimSolver
from tests.common import minimal_project


def _expect(solver, e):
    """eval_one's outcome computed through eval_upto(e, 2), the path it used before."""
    try:
        r = solver.eval_upto(e, 2)
    except SimUnsatError:
        return "unsat"
    return r[0] if len(r) == 1 else "multi"


def _got(solver, e):
    try:
        return solver.eval_one(e)
    except SimUnsatError:  # a SimValueError
        return "unsat"
    except SimValueError:
        return "multi"


class TestEvalUnique(unittest.TestCase):
    def _solvers(self):
        proj = minimal_project("AMD64")
        out = []
        for frontend in (claripy.Solver(), claripy.SolverReplacement(auto_replace=False)):
            s = angr.SimState(project=proj, mode="symbolic")
            s.register_plugin("solver", SimSolver(frontend))
            out.append(s)
        return out

    def test_matches_eval_upto(self):
        x, y, z = claripy.BVS("x", 32), claripy.BVS("y", 32), claripy.BVS("z", 32)
        for state in self._solvers():
            solver = state.solver
            solver.add(y == 7)
            solver.add(claripy.ULT(z, 2))
            solver.eval(y)  # warm the model cache
            exprs = [
                y + 1, x + y, x ^ x, (x & 0) + y, z, z + y, claripy.ULE(x, 0xFFFFFFFF), x == x + 1,
                claripy.If(x == 3, y, y), claripy.Concat(x, y), y * 3, claripy.BVV(4, 32),
            ]
            for e in exprs:
                assert _got(solver, e) == _expect(solver, e), e
            solver.add(y == 8)
            assert _got(solver, y) == "unsat"

    def test_two_completions_avoid_backend(self):
        x, y = claripy.BVS("x", 32), claripy.BVS("y", 32)
        state = self._solvers()[1]
        solver = state.solver
        solver.add(y == 7)
        solver.eval(y)
        assert solver._solver.eval_unique(x + y)[0] != solver._solver.eval_unique(x + y)[1]
        assert solver._solver.eval_unique(y + 1) == [8]


if __name__ == "__main__":
    unittest.main()
