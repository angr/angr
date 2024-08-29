#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCfgVexPostprocessor(unittest.TestCase):
    def test_issue_1172(self):
        path = os.path.join(test_location, "x86_64", "cfg_issue_1172")
        p = angr.Project(path, auto_load_libs=False)

        # it should not crash
        _ = p.analyses.CFG()


if __name__ == "__main__":
    unittest.main()
