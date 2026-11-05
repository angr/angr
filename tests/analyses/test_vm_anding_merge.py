#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import claripy
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver

A, B = 0x655E3, 0x6E362  # the two targets a VM branch selects between


class TestAndingMerge(unittest.TestCase):
    """Merging the VM states' constraints keeps a split condition pinned only where every side pinned it."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.states = []

    def _solver(self, *pins):
        s = self.proj.factory.blank_state(addr=0x1000, mode="fastpath")
        s.register_plugin(
            "partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement(auto_replace=False))
        )
        self.states.append(s)  # the plugin holds its state weakly
        for pin in pins:
            s.partial_symbolic_constraint_solver.add(pin)
        return s.partial_symbolic_constraint_solver

    def _merge(self, *solvers):
        merged = solvers[0].copy()
        merged.merge(list(solvers[1:]), None)
        return merged._solver

    def test_a_pin_one_side_lacks_is_dropped(self):
        c, d = claripy.BoolS("mba_state_split_cond_1"), claripy.BoolS("mba_state_split_cond_2")
        vip = claripy.If(c, claripy.BVV(A, 64), claripy.BVV(B, 64))
        merged = self._merge(self._solver(c, d), self._solver(claripy.Not(d)))
        assert sorted(merged.eval(vip, 3)) == [A, B]
        assert sorted(merged.eval(d, 3)) == [False, True]

    def test_pins_on_every_side(self):
        c = claripy.BoolS("mba_state_split_cond_1")
        vip = claripy.If(c, claripy.BVV(A, 64), claripy.BVV(B, 64))
        # alike on all three sides: kept
        merged = self._merge(self._solver(c), self._solver(c), self._solver(c))
        assert list(merged.eval(vip, 3)) == [A]
        # one side pins it twice: still that side's pin, not an OR of its two
        d = claripy.BoolS("mba_state_split_cond_2")
        merged = self._merge(self._solver(d, d == claripy.true()), self._solver(d))
        assert list(merged.eval(d, 3)) == [True]


if __name__ == "__main__":
    unittest.main()
