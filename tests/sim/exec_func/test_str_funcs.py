#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
__package__ = __package__ or "tests.sim.exec_func"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestStrFuncs(unittest.TestCase):
    def test_strncpy(self):
        # auto_load_libs can't be disabled as the test cases failed.
        strncpy_amd64 = angr.Project(
            os.path.join(test_location, "x86_64", "strncpy"),
            load_options={"auto_load_libs": True},
            exclude_sim_procedures_list=["strncpy"],
        )
        explorer = strncpy_amd64.factory.simulation_manager()
        explorer.explore(find=[0x4005FF])
        s = explorer.found[0]
        result = s.solver.eval(s.memory.load(s.regs.rax, 16), cast_to=bytes)
        assert result == b"why hello there\0"

    def test_strncpy_size(self):
        # auto_load_libs can't be disabled as the test cases failed.
        strncpy_size_amd64 = angr.Project(
            os.path.join(test_location, "x86_64", "strncpy-size"),
            load_options={"auto_load_libs": True},
            exclude_sim_procedures_list=["strncpy"],
        )
        explorer = strncpy_size_amd64.factory.simulation_manager()
        cfg = strncpy_size_amd64.analyses.CFG(objects=[strncpy_size_amd64.loader.main_object], normalize=True)
        explorer.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=50))
        explorer.explore(find=[0x40064C])
        s = explorer.found[0]
        result = s.solver.eval(s.memory.load(s.regs.rax, 40), cast_to=bytes)
        assert result == b"just testing things\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

    def test_strncpy_verify_null(self):
        # auto_load_libs can't be disabled as the test cases failed.
        strncpy_verify_null_amd64 = angr.Project(
            os.path.join(test_location, "x86_64", "strncpy-verify-null"),
            load_options={"auto_load_libs": True},
            exclude_sim_procedures_list=["strncpy"],
        )
        explorer = strncpy_verify_null_amd64.factory.simulation_manager()
        cfg = strncpy_verify_null_amd64.analyses.CFG(
            objects=[strncpy_verify_null_amd64.loader.main_object], normalize=True
        )
        explorer.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=50))
        explorer.explore(find=[0x40064C])
        s = explorer.found[0]
        result = s.solver.eval(s.memory.load(s.regs.rax, 40), cast_to=bytes)
        assert result == b"just testing things\0\0\0\0\0\0\0\0\0\0\0\0\0\0AAAAAA\0"

    def test_strstr_and_strncpy(self):
        # auto_load_libs can't be disabled as the test cases failed.
        strstr_and_strncpy_amd64 = angr.Project(
            os.path.join(test_location, "x86_64", "strstr_and_strncpy"),
            load_options={"auto_load_libs": True},
            exclude_sim_procedures_list=["strstr"],
        )
        explorer = strstr_and_strncpy_amd64.factory.simulation_manager()
        cfg = strstr_and_strncpy_amd64.analyses.CFG(
            objects=[strstr_and_strncpy_amd64.loader.main_object], normalize=True
        )
        explorer.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=50))
        explorer.explore(find=[0x400657])
        s = explorer.found[0]
        result = s.solver.eval(s.memory.load(s.regs.rax, 15), cast_to=bytes)
        assert result == b"hi th hi there\0"

    def test_strstr(self):
        # auto_load_libs can't be disabled as the test cases failed.
        strstr_amd64 = angr.Project(
            os.path.join(test_location, "x86_64", "strstr"),
            load_options={"auto_load_libs": True},
            exclude_sim_procedures_list=["strstr"],
        )
        explorer = strstr_amd64.factory.simulation_manager()
        explorer.explore(find=[0x4005FB])
        s = explorer.found[0]
        result = s.solver.eval(s.memory.load(s.regs.rax, 9), cast_to=bytes)
        assert result == b"hi there\0"


if __name__ == "__main__":
    unittest.main()
