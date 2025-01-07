#!/usr/bin/env python3
from __future__ import annotations

import os
import unittest

import claripy

import angr

from tests.common import bin_location, slow_test


# pylint: disable=missing-class-docstring
class TestMemcmpDefiniteSize(unittest.TestCase):
    @slow_test
    def test_memcmp_strlen_simprocedure_interaction(self):
        bin_path = os.path.join(bin_location, "i386", "cpp_regression_test_ch25")

        p = angr.Project(bin_path, auto_load_libs=True)  # this binary requires the loading of libstdc++.so.6
        argv1 = claripy.Concat(*[claripy.BVS(f"argv{i}", 8) for i in range(48)])

        state = p.factory.full_init_state(args=[bin_path, argv1], add_options=angr.sim_options.unicorn)

        sm = p.factory.simulation_manager(state)
        x = sm.explore(find=0x8048B9B, num_find=2)

        self.assertEqual(len(x.found), 1)
        for state in x.found:
            solution = state.solver.eval_one(argv1, cast_to=bytes).strip(b"\x00")
            self.assertEqual(solution, b"Here_you_have_to_understand_a_little_C++_stuffs")


if __name__ == "__main__":
    unittest.main()
