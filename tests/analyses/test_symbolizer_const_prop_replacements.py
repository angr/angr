#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest
import weakref
from unittest import mock

import pyvex

import angr
from angr import claripy
from angr.analyses.symbolizer.symbolizer import PropagatorEmulatedEngine, PropagatorVEXState
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver
from angr.code_location import CodeLocation


class TestSymbolizerConstPropReplacements(unittest.TestCase):
    """The constant-propagation bookkeeping of PropagatorEmulatedEngine._handle_vex_expr."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x48\xc7\xc0\x05\x00\x00\x00\xc3", "amd64")  # mov rax, 5; ret
        self.engine = PropagatorEmulatedEngine(project=self.proj)
        state = self.proj.factory.blank_state()
        state.register_plugin(
            "partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement(auto_replace=False))
        )
        self.abstract = PropagatorVEXState(self.proj.arch)
        for k, v in {
            "cur_block_id": None,
            "abstract_state": weakref.ref(self.abstract),
            "is_symbolizer": False,
            "is_constant_propagation": True,
            "constant_prop_level": 0,
            "last_added_state_split_cond": None,
        }.items():
            state.globals[k] = v
        self.state = state
        self.engine.state = state
        self.engine.irsb = self.proj.factory.block(0x0).vex
        self.engine.stmt_idx = 1
        self.loc = CodeLocation(self.engine.irsb.addr, 1, block_id=None)

    def _run(self, expr, value):
        parent = next(k for k in PropagatorEmulatedEngine.__mro__[1:] if "_handle_vex_expr" in k.__dict__)
        with mock.patch.object(parent, "_handle_vex_expr", lambda _self, _e: value):
            return self.engine._handle_vex_expr(expr)

    def test_constant_then_conflict_then_top(self):
        expr = pyvex.expr.Get(16, "Ity_I64")
        assert self._run(expr, claripy.BVV(5, 64)).concrete_value == 5
        assert self.abstract._replacements[self.loc][expr].con.value == 5
        # same value again: unchanged
        self._run(expr, claripy.BVV(5, 64))
        assert self.abstract._replacements[self.loc][expr].con.value == 5
        # a different constant: TOP
        self._run(expr, claripy.BVV(6, 64))
        assert self.abstract._replacements[self.loc][expr] == "TOP"
        # TOP short-circuits and returns the unsimplified result
        sym = claripy.BVS("y", 64)
        assert self._run(expr, sym) is sym

    def test_symbolic_after_constant_is_top(self):
        expr = pyvex.expr.Get(24, "Ity_I64")
        self._run(expr, claripy.BVV(7, 64))
        self._run(expr, claripy.BVS("z", 64))
        assert self.abstract._replacements[self.loc][expr] == "TOP"
        # a constant expression never gets an entry
        const = pyvex.expr.Const(pyvex.const.U64(3))
        self._run(const, claripy.BVV(3, 64))
        assert const not in self.abstract._replacements[self.loc]


if __name__ == "__main__":
    unittest.main()
