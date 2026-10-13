#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location


class TestStrtol(unittest.TestCase):
    # pylint: disable=no-self-use

    def test_strtol(self, threads=None):
        test_bin = os.path.join(bin_location, "tests", "x86_64", "strtol_test")
        # disabling auto_load_libs increases the execution time of the test case.
        b = angr.Project(test_bin, auto_load_libs=True)

        initial_state = b.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
        pg = b.factory.simulation_manager(thing=initial_state, threads=threads)

        # find the end of main
        expected_outputs = {
            b"base 8 worked\n",
            b"base +8 worked\n",
            b"0x worked\n",
            b"+0x worked\n",
            b"base +10 worked\n",
            b"base 10 worked\n",
            b"base -8 worked\n",
            b"-0x worked\n",
            b"base -10 worked\n",
            b"Nope\n",
        }
        pg.explore(find=0x400804, num_find=len(expected_outputs))
        assert len(pg.found) == len(expected_outputs)

        # check that the outputs are correct
        outputs = {f.posix.dumps(1) for f in pg.found}
        assert outputs == expected_outputs

    def test_strtol_long_string(self):
        # convert a 11-digit long string to a number.
        # there was an off-by-one error before.

        b = angr.load_shellcode(b"\x90\x90", "AMD64")
        state = b.factory.blank_state()
        state.memory.store(0x500000, b"98831114236\x00")

        state.libc.max_strtol_len = 11

        strtol = angr.SIM_LIBRARIES["libc.so.6"][0].get("strtol", arch=b.arch)
        strtol.state = state.copy()
        ret = strtol.run(0x500000, 0, 0)

        assert strtol.state.satisfiable()
        assert len(strtol.state.solver.eval_upto(ret, 2)) == 1
        assert strtol.state.solver.eval_one(ret) == 98831114236

    def test_strtol_small_bases(self):
        # digits must be below the base: '8' is not octal, '2' is not binary
        p = angr.load_shellcode(b"\x90", arch="amd64")
        strtol = angr.SIM_PROCEDURES["libc"]["strtol"]()
        src, endptr = 0x100000, 0x200000
        for text, base, value, consumed in [
            (b"78", 8, 7, 1),
            (b"12", 2, 1, 1),
            (b"08", 0, 0, 1),
            (b"755", 8, 0o755, 3),
        ]:
            state = p.factory.blank_state()
            state.memory.store(src, text + b"\x00")
            ret = strtol.execute(state, arguments=[src, endptr, base]).ret_expr
            assert state.solver.eval_one(ret) == value, (text, base)
            end = state.solver.eval_one(state.memory.load(endptr, 8, endness=p.arch.memory_endness))
            assert end == src + consumed, (text, base)

    def test_strtol_uppercase_hex_prefix(self):
        p = angr.load_shellcode(b"\x90", arch="amd64")
        strtol = angr.SIM_PROCEDURES["libc"]["strtol"]()
        src, endptr = 0x100000, 0x200000
        for text, base, value in [(b"0X1f", 16, 0x1F), (b"0X1f", 0, 0x1F), (b"-0X10", 0, -0x10 & 0xFFFFFFFFFFFFFFFF)]:
            state = p.factory.blank_state()
            state.memory.store(src, text + b"\x00")
            ret = strtol.execute(state, arguments=[src, endptr, base]).ret_expr
            assert state.solver.eval_one(ret) == value, (text, base)


if __name__ == "__main__":
    unittest.main()
