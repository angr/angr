#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


class TestSpillingFunctionDictCopy(unittest.TestCase):
    def test_copy_with_spilled_functions(self):
        # small binaries do not spill by default; request a spilling function map, then shrink it
        proj = angr.Project(FAUXWARE, auto_load_libs=False, cache_limits={"functions": 100})
        proj.analyses.CFGFast()
        sfd = proj.kb.functions._function_map
        sfd._db_batch_size = 1
        sfd.cache_limit = 5
        assert sfd.spilled_count > 0

        copied = sfd.copy()

        assert len(copied) == len(sfd)
        assert set(copied) == set(sfd)
        assert copied.cached_count == sfd.cached_count
        assert copied.spilled_count == sfd.spilled_count
        for addr in list(sfd._spilled_keys)[:3]:
            assert addr in copied
            assert copied[addr].addr == addr


if __name__ == "__main__":
    unittest.main()
