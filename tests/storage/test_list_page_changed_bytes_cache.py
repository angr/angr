#!/usr/bin/env python3
# pylint:disable=missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.storage"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import claripy
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver
from angr.storage.memory_mixins import DefaultListPagesMemory

ADDR = 0x500000


class TestListPageChangedBytesCache(unittest.TestCase):
    """changed_bytes() with pre-merge states solves each memory object once, not once per byte."""

    @classmethod
    def setUpClass(cls):
        cls._old_mem = angr.SimState._presets["default"]._default_plugins["sym_memory"]
        angr.SimState._presets["default"]._default_plugins["sym_memory"] = DefaultListPagesMemory
        cls.proj = angr.load_shellcode(b"\x90", "amd64")

    @classmethod
    def tearDownClass(cls):
        angr.SimState._presets["default"]._default_plugins["sym_memory"] = cls._old_mem

    def _state(self, name, *values):
        state = self.proj.factory.blank_state()
        state.register_plugin(
            "partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement(auto_replace=False))
        )
        var = claripy.BVS(name, 64)
        if values:
            state.partial_symbolic_constraint_solver.add(claripy.Or(*[var == v for v in values]))
        state.memory.store(ADDR, var)
        solver = state.partial_symbolic_constraint_solver
        calls = []
        depth = [0]  # eval_one calls eval_upto internally; count only outermost calls
        for name_ in ("eval_one", "eval_upto"):
            orig = getattr(solver, name_)

            def counting(*args, _orig=orig, _name=name_, **kwargs):
                if depth[0] == 0:
                    calls.append(_name)
                depth[0] += 1
                try:
                    return _orig(*args, **kwargs)
                finally:
                    depth[0] -= 1

            setattr(solver, name_, counting)
        return state, calls

    def _diff(self, s0, s1):
        changes = s0.memory.changed_pages(s1.memory, [s0, s1])
        return changes.get(ADDR >> 12)

    def test_equal_solutions_are_not_a_difference(self):
        s0, c0 = self._state("x", 0x1122334455667788)
        s1, c1 = self._state("y", 0x1122334455667788)
        assert not self._diff(s0, s1)
        assert c0 == ["eval_upto"] and c1 == ["eval_upto"]

    def test_different_solutions_differ_in_every_byte(self):
        s0, c0 = self._state("x", 0x1122334455667788)
        s1, c1 = self._state("y", 0x8877665544332211)
        assert self._diff(s0, s1) == set(range(8))
        assert c0 == ["eval_upto"] and c1 == ["eval_upto"]

    def test_two_witnesses_prove_multi_valued_bytes(self):
        s0, c0 = self._state("x", 0x1122334455667788)
        s1, c1 = self._state("y", 0x1111111111111111, 0x2222222222222222)
        assert self._diff(s0, s1) == set(range(8))
        # the two solutions differ in every byte, so no byte needs its own solve
        assert c0 == ["eval_upto"] and c1 == ["eval_upto"]

    def test_unconstrained_object_falls_back_to_bytes(self):
        s0, c0 = self._state("x", 0x1122334455667788)
        s1, c1 = self._state("y")
        assert self._diff(s0, s1) == set(range(8))
        # one whole-object solve, then only the bytes both witnesses agree on are solved alone
        assert c0 == ["eval_upto"]
        assert c1[0] == "eval_upto" and set(c1[1:]) <= {"eval_one"} and len(c1) <= 9


if __name__ == "__main__":
    unittest.main()
