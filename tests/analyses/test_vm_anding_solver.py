#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import claripy
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver

A, B = 0x655E3, 0x6E362  # the two targets a VM branch selects between


class TestAndingSimSolver(unittest.TestCase):
    """The VM states' symbolic solver, on fastpath (non-SYMBOLIC) states."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.cond = claripy.BoolS("mba_state_split_cond_1")
        self.vip = claripy.If(self.cond, claripy.BVV(A, 64), claripy.BVV(B, 64))

    def _solver(self):
        s = self.proj.factory.blank_state(addr=0x1000, mode="fastpath")
        assert angr.sim_options.SYMBOLIC not in s.options
        s.register_plugin(
            "partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement(auto_replace=False))
        )
        self.state = s  # the plugin holds its state weakly
        return s.partial_symbolic_constraint_solver

    def test_satisfiable_solves_extra_constraints(self):
        solver = self._solver()
        assert solver.satisfiable(extra_constraints=[self.vip == A, self.cond])
        assert not solver.satisfiable(extra_constraints=[self.vip == A, claripy.Not(self.cond)])
        assert solver.satisfiable()

    def test_unique_asks_the_solver(self):
        solver = self._solver()
        assert not solver.unique(self.vip)
        solver.add(self.cond)
        assert solver.unique(self.vip)


if __name__ == "__main__":
    unittest.main()
