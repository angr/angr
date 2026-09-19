#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


class TestRebuildCallgraphHooks(unittest.TestCase):
    def test_rebuild_callgraph_adds_no_self_loops_for_hooked_functions(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        proj.analyses.CFGFast()
        fm = proj.kb.functions
        hooked = [f for f in fm.values() if f.startpoint is not None and f.startpoint.is_hook]
        assert hooked

        before = set(fm.callgraph.edges())
        fm.rebuild_callgraph()
        after = set(fm.callgraph.edges())

        assert not any(src == dst for src, dst in after)
        assert after == before


if __name__ == "__main__":
    unittest.main()
