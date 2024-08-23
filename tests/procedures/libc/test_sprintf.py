#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSprintf(unittest.TestCase):
    def test_sprintf(self):
        p = angr.Project(
            os.path.join(test_location, "x86_64", "sprintf_test"),
            auto_load_libs=False,
        )
        a = p.factory.simulation_manager().explore(find=0x4005C0)
        state = a.found[0]

        str1 = state.solver.eval(state.memory.load(0x600AD0, 13), cast_to=bytes)
        assert str1 == b"Immediate: 3\n"

        str2 = state.solver.eval(state.memory.load(0x600A70, 7), cast_to=bytes)
        assert str2 == b"Int: 3\n"

        str3 = state.solver.eval(state.memory.load(0x600AB0, 8), cast_to=bytes)
        assert str3 == b"Char: c\n"

        str4 = state.solver.eval(state.memory.load(0x600A50, 14), cast_to=bytes)
        assert str4 == b"Uninit int: 0\n"

        str5 = state.solver.eval(state.memory.load(0x600A90, 24), cast_to=bytes)
        assert str5 == b"Str on stack: A string.\n"

        str6 = state.solver.eval(state.memory.load(0x600A30, 21), cast_to=bytes)
        assert str6 == b"Global str: GLOB_STR\n"


if __name__ == "__main__":
    unittest.main()
