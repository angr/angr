#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.engines"  # pylint:disable=redefined-builtin

import unittest

import angr


class TestCallstackOptOut(unittest.TestCase):
    @staticmethod
    def _top_func_after_call(manage: bool) -> int:
        # call 0x6; ret | 0x6: ret
        p = angr.load_shellcode(b"\xe8\x01\x00\x00\x00\xc3\xc3", "x86", load_address=0x1000)
        p.manage_callstack = manage
        state = p.factory.blank_state(addr=0x1000)
        assert state.callstack is not None  # only an existing callstack plugin is managed
        simgr = p.factory.simulation_manager(state)
        simgr.step()
        (state,) = simgr.active
        assert state.addr == 0x1006
        return state.callstack.top.func_addr

    def test_managed_by_default(self):
        assert angr.load_shellcode(b"\xc3", "x86").manage_callstack is True
        assert self._top_func_after_call(True) == 0x1006

    def test_opt_out(self):
        assert self._top_func_after_call(False) == 0


if __name__ == "__main__":
    unittest.main()
