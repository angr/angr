#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

import unittest

from angr import SimState, SimFile, SIM_PROCEDURES


class TestPwrite(unittest.TestCase):
    def test_pwrite(self):
        pwrite = SIM_PROCEDURES["posix"]["pwrite64"]()

        state = SimState(arch="AMD64", mode="symbolic")
        simfile = SimFile("concrete_file", content="hello world!\n")
        state.fs.insert("test", simfile)
        fd = state.posix.open(b"test", 1)

        buf_addr = 0xD0000000
        state.memory.store(buf_addr, b"test!")
        pwrite.execute(state, arguments=[fd, buf_addr, 5, 6])

        simfd = state.posix.get_fd(fd)
        simfd.seek(0)
        res = 0xC0000000
        simfd.read(res, 13)
        data = state.solver.eval(state.mem[res].string.resolved, cast_to=bytes)

        assert data == b"hello test!!\n"

        state.posix.close(fd)


class TestPread(unittest.TestCase):
    def test_pread(self):
        pwrite = SIM_PROCEDURES["posix"]["pread64"]()

        state = SimState(arch="AMD64", mode="symbolic")
        simfile = SimFile("concrete_file", content="hello world!\n")
        state.fs.insert("test", simfile)
        fd = state.posix.open(b"test", 1)

        buf1_addr = 0xD0000000
        buf2_addr = 0xD0001000
        pwrite.execute(state, arguments=[fd, buf1_addr, 6, 6])
        pwrite.execute(state, arguments=[fd, buf2_addr, 5, 0])

        data1 = state.solver.eval(state.mem[buf1_addr].string.resolved, cast_to=bytes)
        data2 = state.solver.eval(state.mem[buf2_addr].string.resolved, cast_to=bytes)

        assert data1 == b"world!"
        assert data2 == b"hello"

        state.posix.close(fd)


if __name__ == "__main__":
    unittest.main()
