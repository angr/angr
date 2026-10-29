#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.state_plugins.inspect"  # pylint:disable=redefined-builtin

from unittest import TestCase, main

import angr
from angr import claripy
from angr.state_plugins.inspect import BP_AFTER, BP_BEFORE
from angr.state_plugins.sim_action_object import SimActionObject, _raw_ast


class TestInspectActionFastPath(TestCase):
    def _state(self):
        proj = angr.load_shellcode(b"\xc3", "amd64")
        s = proj.factory.blank_state()
        s.inspect  # pylint:disable=pointless-statement
        return s

    def test_no_breakpoint_publishes_attrs(self):
        s = self._state()
        s.inspect.action_attrs_set = True
        s._inspect("expr", BP_BEFORE, expr=1, expr_result=2)
        assert s.inspect.attrs.expr == 1 and s.inspect.attrs.expr_result == 2
        assert s._inspect_getattr("expr_result", None) == 2
        assert s.inspect.action_attrs_set is False
        with self.assertRaises(ValueError):
            s._inspect("expr", BP_BEFORE, not_an_attr=1)

    def test_breakpoint_still_fires_and_can_override(self):
        s = self._state()
        hits = []

        def bp(state):
            hits.append(state.inspect.attrs.expr_result)
            state.inspect.attrs.expr_result = 7

        s.inspect.b("expr", when=BP_AFTER, action=bp)
        s._inspect("expr", BP_AFTER, expr_result=3)
        assert hits == [3]
        assert s._inspect_getattr("expr_result", None) == 7
        assert s.inspect.action_attrs_set is False
        s._inspect("statement", BP_BEFORE, statement=4)
        assert hits == [3] and s.inspect.attrs.statement == 4

    def test_raw_ast_leaves_and_containers(self):
        x = claripy.BVS("x", 8)
        sao = SimActionObject(x)
        for v in (1, True, None, "s", b"b", 1.5, x, claripy.true(), claripy.FPV(1.0, claripy.FSORT_DOUBLE)):
            assert _raw_ast(v) is v
        assert _raw_ast(sao) is x
        assert _raw_ast((sao, 1)) == (x, 1) and type(_raw_ast([sao])) is list
        assert _raw_ast({"a": sao})["a"] is x


if __name__ == "__main__":
    main()
