#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestRegionIdentifier(unittest.TestCase):
    def test_smoketest(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)
        cfg = p.analyses.CFG(normalize=True)

        main_func = cfg.kb.functions["main"]

        _ = p.analyses.RegionIdentifier(main_func)


if __name__ == "__main__":
    unittest.main()
