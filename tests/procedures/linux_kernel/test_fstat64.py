#!/usr/bin/env python3
from __future__ import annotations

import unittest

import archinfo

from angr import SIM_PROCEDURES, SimFile, SimState
from tests.common import minimal_project

STAT_BUF = 0x100000


def fstat64(state, arguments):
    return SIM_PROCEDURES["linux_kernel"]["fstat64"]().execute(state, arguments=arguments)


def load(state, off, size):
    return state.memory.load(STAT_BUF + off, size, endness=state.arch.memory_endness)


class TestFstat64(unittest.TestCase):
    """Tests for the fstat64 SimProcedure."""

    def test_mips32_layout(self):
        for endness in (archinfo.Endness.BE, archinfo.Endness.LE):
            with self.subTest(endness=endness):
                arch = archinfo.ArchMIPS32(endness)
                state = SimState(project=minimal_project(arch), mode="symbolic")
                state.fs.insert("/tmp/f", SimFile(name="f", content=b"hello"))
                fd = state.posix.open(b"/tmp/f", 0)
                state.memory.store(STAT_BUF, b"\xff" * 0x6C)

                assert state.solver.eval(fstat64(state, [fd, STAT_BUF]).ret_expr) == 0

                assert any(v.startswith("st_mode") for v in load(state, 0x18, 4).variables)
                assert any(v.startswith("st_size") for v in load(state, 0x38, 8).variables)
                assert state.solver.eval_one(load(state, 0x58, 4)) == 0x400  # st_blksize
                # the struct is 0x68 bytes
                assert state.solver.eval_one(load(state, 0x68, 4)) == 0xFFFFFFFF


if __name__ == "__main__":
    unittest.main()
