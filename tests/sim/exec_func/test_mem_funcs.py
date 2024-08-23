#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim.exec_func"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestMemFuncs(unittest.TestCase):
    def test_memmove(self):
        # auto_load_libs can't be disabled as the testcase fails
        proj = angr.Project(
            os.path.join(test_location, "x86_64", "memmove"),
            load_options={"auto_load_libs": True},
            exclude_sim_procedures_list=["memmove"],
        )
        explorer = proj.factory.simulation_manager().explore(find=[0x4005D7])
        s = explorer.found[0]
        result = s.solver.eval(s.memory.load(s.registers.load(16, 8), 13), cast_to=bytes)
        assert result == b"very useful.\x00"

    def test_memcpy(self):
        # auto_load_libs can't be disabled as the testcase fails
        proj = angr.Project(
            os.path.join(test_location, "x86_64", "memcpy"),
            load_options={"auto_load_libs": True},
            exclude_sim_procedures_list=["memcpy"],
        )
        explorer = proj.factory.simulation_manager().explore(find=[0x40065A])
        s = explorer.found[0]
        result = s.solver.eval(s.memory.load(s.registers.load(16, 8), 19), cast_to=bytes)
        assert result == b"let's test memcpy!\x00"

    def test_memset(self):
        # auto_load_libs can't be disabled as the testcase fails
        proj = angr.Project(
            os.path.join(test_location, "x86_64", "memset"),
            load_options={"auto_load_libs": True},
            exclude_sim_procedures_list=["memset"],
        )
        explorer = proj.factory.simulation_manager().explore(find=[0x400608])
        s = explorer.found[0]
        result = s.solver.eval(s.memory.load(s.registers.load(16, 8), 50), cast_to=bytes)
        assert result == b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x00"


if __name__ == "__main__":
    unittest.main()
