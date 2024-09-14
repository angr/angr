#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
import angr.analyses.decompiler

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestClinic(unittest.TestCase):
    def test_smoketest(self):
        binary_path = os.path.join(test_location, "x86_64", "all")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=True)

        cfg = proj.analyses.CFG(normalize=True)
        main_func = cfg.kb.functions["main"]

        proj.analyses.Clinic(main_func)


if __name__ == "__main__":
    unittest.main()
