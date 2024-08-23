#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

import unittest

import angr


class TestSimTime(unittest.TestCase):
    def test_gettimeofday(self):
        proc = angr.SIM_PROCEDURES["posix"]["gettimeofday"]()

        s = angr.SimState(arch="amd64")
        s.regs.rdi = 0x8000
        s.regs.rsi = 0

        s.options.add(angr.options.USE_SYSTEM_TIMES)
        proc.execute(s)
        assert not s.mem[0x8000].qword.resolved.symbolic
        assert not s.mem[0x8008].qword.resolved.symbolic

        s.options.discard(angr.options.USE_SYSTEM_TIMES)
        proc.execute(s)
        assert s.mem[0x8000].qword.resolved.symbolic
        assert s.mem[0x8008].qword.resolved.symbolic

    def test_clock_gettime(self):
        proc = angr.SIM_PROCEDURES["posix"]["clock_gettime"]()

        s = angr.SimState(arch="amd64")
        s.regs.rdi = 0
        s.regs.rsi = 0x8000

        s.options.add(angr.options.USE_SYSTEM_TIMES)
        proc.execute(s)
        assert not s.mem[0x8000].qword.resolved.symbolic
        assert not s.mem[0x8008].qword.resolved.symbolic

        s.options.discard(angr.options.USE_SYSTEM_TIMES)
        proc.execute(s)
        assert s.mem[0x8000].qword.resolved.symbolic
        assert s.mem[0x8008].qword.resolved.symbolic


if __name__ == "__main__":
    unittest.main()
