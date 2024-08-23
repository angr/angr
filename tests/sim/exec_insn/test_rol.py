#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim.exec_insn"  # pylint:disable=redefined-builtin

import os
import unittest

import claripy

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestRol(unittest.TestCase):
    def test_rol_x86_64(self):
        binary_path = os.path.join(test_location, "x86_64", "test_rol.exe")

        proj = angr.Project(binary_path, auto_load_libs=False)

        initial_state = proj.factory.blank_state(addr=0x401000)
        r_rax = claripy.BVS("rax", 64)
        initial_state.regs.rax = r_rax

        pg = proj.factory.simulation_manager(initial_state)
        pg.explore(find=0x401013, avoid=0x401010)
        found_state = pg.found[0]

        result = found_state.solver.eval(r_rax)
        assert result == 0x37B7AB70

    def test_rol_i386(self):
        binary_path = os.path.join(test_location, "i386", "test_rol.exe")

        proj = angr.Project(binary_path, auto_load_libs=False)

        initial_state = proj.factory.blank_state(addr=0x401000)
        r_eax = claripy.BVS("eax", 32)
        initial_state.regs.eax = r_eax

        pg = proj.factory.simulation_manager(initial_state)
        pg.explore(find=0x401013, avoid=0x401010)
        found_state = pg.found[0]

        result = found_state.solver.eval(r_eax)
        assert result == 0x37B7AB70


if __name__ == "__main__":
    unittest.main()
