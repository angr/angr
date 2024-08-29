#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


def _bin(*s):
    return os.path.join(bin_location, "tests", *s)


class TestSimpleApi(unittest.TestCase):
    def test_fauxware(self):
        project = angr.Project(_bin("i386", "fauxware"), auto_load_libs=False)

        result = [0, 0]

        @project.hook(0x80485DB)
        def check_backdoor(state):  # pylint:disable=unused-variable
            result[0] += 1
            if b"SOSNEAKY" in state.posix.dumps(0):
                result[1] = True
                project.terminate_execution()

        pg = project.execute()
        assert len(pg.deadended) != 3  # should terminate early
        assert result[1]


if __name__ == "__main__":
    unittest.main()
