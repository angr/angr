#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


class TestFunctionCacheLimitOverride(unittest.TestCase):
    def test_explicit_limits_are_not_clamped(self):
        for limit in (7, 20000, None):
            proj = angr.Project(FAUXWARE, auto_load_libs=False, cache_limits={"functions": limit})
            assert proj.kb.functions.cache_limit == limit


if __name__ == "__main__":
    unittest.main()
