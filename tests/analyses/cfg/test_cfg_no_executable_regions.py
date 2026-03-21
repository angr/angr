#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCfgNoExeutableRegions(unittest.TestCase):
    def test_cfg_no_exec_regions_65e25ea2(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "65e25ea21a2f873affee8034e2c3381df48ff4129d447fa288fbd92307647582"
        )
        p = angr.Project(bin_path)
        cfg = p.analyses.CFG()
        assert len(cfg.kb.functions) == 0


if __name__ == "__main__":
    unittest.main()
