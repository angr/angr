#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import slow_test, bin_location


class TestStrtol(unittest.TestCase):
    # pylint: disable=no-self-use

    @slow_test
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


if __name__ == "__main__":
    unittest.main()
