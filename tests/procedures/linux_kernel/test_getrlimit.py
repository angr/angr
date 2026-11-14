#!/usr/bin/env python3
from __future__ import annotations

import unittest

import archinfo

from angr import SIM_PROCEDURES, SimState
from tests.common import minimal_project

RLIM_BUF = 0x100000
RLIMIT_STACK = 3


def getrlimit(state, arguments):
    return SIM_PROCEDURES["linux_kernel"]["getrlimit"]().execute(state, arguments=arguments)


class TestGetrlimit(unittest.TestCase):
    def test_rlimit_stack_layout(self):
        for arch in (archinfo.ArchAMD64(), archinfo.ArchX86(), archinfo.ArchMIPS32(archinfo.Endness.BE)):
            with self.subTest(arch=arch.name):
                state = SimState(project=minimal_project(arch), mode="symbolic")
                state.memory.store(RLIM_BUF, b"\xff" * (2 * arch.bytes + 4))

                assert state.solver.eval(getrlimit(state, [RLIMIT_STACK, RLIM_BUF]).ret_expr) == 0

                endness = arch.memory_endness
                rlim_cur = state.memory.load(RLIM_BUF, arch.bytes, endness=endness)
                rlim_max = state.memory.load(RLIM_BUF + arch.bytes, arch.bytes, endness=endness)
                assert state.solver.eval_one(rlim_cur) == 8388608
                assert rlim_max.symbolic
                # nothing is written past the struct
                assert state.solver.eval_one(state.memory.load(RLIM_BUF + 2 * arch.bytes, 4)) == 0xFFFFFFFF


if __name__ == "__main__":
    unittest.main()
