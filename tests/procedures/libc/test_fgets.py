#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest
from itertools import product

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import angr
from angr import claripy
from tests.common import bin_location


class TestFgets(unittest.TestCase):
    TARGET_APP = os.path.join(bin_location, "tests", "x86_64", "fgets")

    def setUp(self):
        self.p = angr.Project(TestFgets.TARGET_APP, auto_load_libs=False)

        self.find_normal = self.p.loader.find_symbol("find_normal").rebased_addr
        self.find_exact = self.p.loader.find_symbol("find_exact").rebased_addr
        self.find_eof = self.p.loader.find_symbol("find_eof").rebased_addr
        self.find_impossible = self.p.loader.find_symbol("find_impossible").rebased_addr

    def _testfind(self, addr, failmsg):
        e = self.p.factory.entry_state()
        e.options.add(angr.sim_options.SHORT_READS)
        e.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        s = self.p.factory.simgr(e)
        r = s.explore(find=addr)
        assert len(r.found) > 0, failmsg
        return r.found[0].posix.dumps(0)

    def _testnotfind(self, addr, failmsg):
        e = self.p.factory.entry_state()
        e.options.add(angr.sim_options.SHORT_READS)
        e.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        s = self.p.factory.simgr(e)
        r = s.explore(find=addr)
        assert len(r.found) == 0, failmsg

    def test_normal(self):
        answer = self._testfind(self.find_normal, "Normal Failure!")
        assert answer == b"normal\n"

    def test_exact(self):
        answer = self._testfind(self.find_exact, "Exact Failure!")
        assert answer.endswith(b"0123456789")

    def test_impossible(self):
        self._testnotfind(self.find_impossible, "Impossible Failure!")

    def test_symbolic_file_lines(self):
        cases = (
            (False, b"A\nB\n", (b"A\n", b"B\n")),
            (True, b"A\nB\n", (b"A\n", b"B\n")),
            (True, b"\n\nZ", (b"\n", b"\n", b"Z")),
            (True, b"AB\nC", (b"AB\n", b"C")),
            (True, b"ABCD\n", (b"ABC", b"D\n")),
            (True, b"AB", (b"AB",)),
        )
        for file_type, short_reads, (has_end, data, lines) in product(
            (angr.SimFile, angr.SimFileStream), (False, True), cases
        ):
            with self.subTest(file_type=file_type.__name__, short_reads=short_reads, has_end=has_end, data=data):
                content = claripy.BVS("stdin", len(data) * 8)
                stdin = file_type(name="stdin", content=content, has_end=has_end)
                state = self.p.factory.blank_state(stdin=stdin)
                if short_reads:
                    state.options.add(angr.options.SHORT_READS)
                fd_offset = io_file_data_for_arch(state.arch)["fd"]
                state.mem[0x2000 + fd_offset].int = 0
                position = 0
                for line in lines:
                    state.memory.store(0x3000, b"_" * 5)
                    angr.SIM_PROCEDURES["libc"]["fgets"]().execute(
                        state, arguments=[0x3000, claripy.BVV(4, state.arch.sizeof["int"]), 0x2000]
                    )
                    state.add_constraints(content == data)
                    assert state.solver.satisfiable()
                    expected = (line + b"\0").ljust(5, b"_")
                    assert state.solver.eval_upto(state.memory.load(0x3000, 5), 2, cast_to=bytes) == [expected]
                    position += len(line)
                    assert state.solver.eval_upto(state.posix.get_fd(0).read_pos, 2) == [position]


if __name__ == "__main__":
    unittest.main()
