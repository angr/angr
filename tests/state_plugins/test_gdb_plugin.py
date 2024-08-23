#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.state_plugins"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")
data_location = os.path.join(bin_location, "tests_data", "test_gdb_plugin")


class TestGdbPlugin(unittest.TestCase):
    def test_gdb(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "test_gdb_plugin"), auto_load_libs=False)
        st = p.factory.blank_state()

        st.gdb.set_stack(os.path.join(data_location, "stack"), stack_top=0x7FFFFFFFF000)
        st.gdb.set_heap(os.path.join(data_location, "heap"), heap_base=0x601000)
        st.gdb.set_regs(os.path.join(data_location, "regs"))

        assert st.solver.eval(st.regs.rip) == 0x4005B4

        # Read the byte in memory at $sp + 8
        loc = st.solver.eval(st.regs.rsp) + 8
        val = st.memory.load(loc, 8, endness=st.arch.memory_endness)
        assert st.solver.eval(val) == 0x00601010


if __name__ == "__main__":
    unittest.main()
