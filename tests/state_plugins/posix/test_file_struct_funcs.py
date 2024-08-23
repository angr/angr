#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.state_plugins.posix"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestFileStructFuncs(unittest.TestCase):
    def check_state_1(self, state):
        # Need to dump file.txt by path because program closes it
        return (
            state.posix.dump_file_by_path("file.txt") == b"testing abcdef"
            and state.posix.dumps(0)[:4] == b"xyz\n"
            and state.posix.dumps(1) == b"good1\n"
            and state.posix.dumps(2) == b""
        )

    def check_state_2(self, state):
        return (
            state.posix.dump_file_by_path("file.txt") == b"testing abcdef"
            and state.posix.dumps(0)[:4] == b"wxyz"
            and state.posix.dumps(1) == b""
            and state.posix.dumps(2) == b"good2\n"
        )

    def check_state_3(self, state):
        return (
            state.posix.dump_file_by_path("file.txt") == b"testing abcdef"
            and state.posix.dumps(1) == b""
            and state.posix.dumps(2) == b""
        )

    def test_file_struct_funcs(self):
        test_bin = os.path.join(test_location, "x86_64", "file_func_test")
        b = angr.Project(test_bin, auto_load_libs=False)

        pg = b.factory.simulation_manager()
        pg.active[0].options.discard("LAZY_SOLVES")
        pg.explore()

        assert len(pg.deadended) == 3

        for p in pg.deadended:
            assert self.check_state_1(p) or self.check_state_2(p) or self.check_state_3(p)


if __name__ == "__main__":
    unittest.main()
