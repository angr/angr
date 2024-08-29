#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.state_plugins"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestMultiOpenFile(unittest.TestCase):
    def test_multi_open_file(self):
        test_bin = os.path.join(test_location, "x86_64", "test_multi_open_file")
        # auto_load_libs cannot be disabled as the test fails
        b = angr.Project(test_bin)

        pg = b.factory.simulation_manager()
        pg.active[0].options.discard("LAZY_SOLVES")
        pg.explore()

        assert len(pg.deadended) == 1

        # See the source file in binaries/tests_src/test_multi_open_file.c
        # for the tests run
        for p in pg.deadended:
            assert p.posix.dumps(2) == b""

            # Check that the temp file was deleted
            assert p.fs._files == {}

            # Check that the deleted temp file contained the appropriate string
            for event in p.history.events:
                if event.type == "fs_unlink":
                    simfile = p.fs.unlinks[event.objects["unlink_idx"]][1]
                    assert simfile.concretize() == b"foobar and baz"
                    break
            else:
                assert False


if __name__ == "__main__":
    unittest.main()
