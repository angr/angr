#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.factory"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestWindowsArgs(unittest.TestCase):
    def test_i386(self):
        after_puts = 0x40105B
        else_paths = [0x401062, 0x401009]

        p = angr.Project(os.path.join(test_location, "i386", "simple_windows.exe"), auto_load_libs=False)

        s = p.factory.entry_state(args=("simple_windows.exe", "angr_can_windows?", "1497715489"))
        simgr = p.factory.simulation_manager(s)
        simgr.explore(find=after_puts, avoid=else_paths, num_find=10)

        assert len(simgr.avoid) == 0
        assert len(simgr.found) > 0
        for f in simgr.found:
            assert b"ok" in f.posix.dumps(1)


if __name__ == "__main__":
    logging.getLogger("angr.engines").setLevel("INFO")
    unittest.main()
