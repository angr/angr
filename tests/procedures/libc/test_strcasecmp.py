#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest

import claripy

import angr

from ...common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestStrCaseCmp(unittest.TestCase):
    def test_i386(self):
        p = angr.Project(os.path.join(test_location, "i386", "test_strcasecmp"), auto_load_libs=False)
        arg1 = claripy.BVS("arg1", 20 * 8)
        s = p.factory.entry_state(args=("test_strcasecmp", arg1))
        sm = p.factory.simulation_manager(s)
        sm.explore()

        sm.move("deadended", "found", filter_func=lambda s: b"Welcome" in s.posix.dumps(1))

        assert len(sm.found) == 1

        f = sm.found[0]
        sol = f.solver.eval(arg1, cast_to=bytes)
        assert b"\x00" in sol
        assert sol[: sol.index(b"\x00")].lower() == b"letmein"
        assert b"wchar works" in f.posix.dumps(1)


if __name__ == "__main__":
    unittest.main()
