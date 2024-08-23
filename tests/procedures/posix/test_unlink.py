#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

import unittest

import angr


class TestUnlink(unittest.TestCase):
    def test_file_unlink(self):
        # Initialize a blank state with an arbitrary errno location
        state = angr.SimState(arch="AMD64", mode="symbolic")
        state.libc.errno_location = 0xA0000000
        state.libc.errno = 0

        # Create a file 'test'
        fd = state.posix.open(b"test", 1)
        state.posix.close(fd)

        # Ensure 'test' was in fact created
        assert b"/test" in state.fs._files

        # Store the filename in memory
        path_addr = 0xB0000000
        state.memory.store(path_addr, b"test\x00")

        # Unlink 'test': should return 0 and leave ERRNO unchanged
        unlink = angr.SIM_PROCEDURES["posix"]["unlink"]()
        state.scratch.sim_procedure = unlink
        rval = unlink.execute(state, arguments=[path_addr]).ret_expr
        assert rval == 0
        assert state.solver.eval(state.libc.errno) == 0

        # Check that 'test' was in fact deleted
        assert state.fs._files == {}

        # Unlink again: should return -1 and set ERRNO to ENOENT
        unlink = angr.SIM_PROCEDURES["posix"]["unlink"]()
        state.scratch.sim_procedure = unlink
        rval = unlink.execute(state, arguments=[path_addr]).ret_expr
        assert rval == -1
        assert state.solver.eval(state.libc.errno) == state.posix.ENOENT


if __name__ == "__main__":
    unittest.main()
