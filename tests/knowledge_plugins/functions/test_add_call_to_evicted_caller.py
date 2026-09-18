#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")
from angr.codenode import FuncNode


class TestAddCallToEvictedCaller(unittest.TestCase):
    def test_call_edge_survives_callee_load_eviction(self):
        # small binaries do not spill by default; request a spilling function map, then shrink it
        proj = angr.Project(FAUXWARE, auto_load_libs=False, cache_limits={"functions": 100})
        proj.analyses.CFGFast()
        fm = proj.kb.functions
        caller_addr = fm["main"].addr
        callee_addr = fm["authenticate"].addr
        block_addr = caller_addr

        sfd = fm._function_map
        sfd._db_batch_size = 1
        sfd.cache_limit = 1
        _ = fm[callee_addr]
        _ = fm[caller_addr]  # loading the caller evicts the callee
        assert sfd.is_cached(caller_addr)
        assert callee_addr in sfd._spilled_keys

        # loading the callee inside _add_call_to evicts the caller; the new edge must not be lost
        fm._add_call_to(caller_addr, block_addr, callee_addr, None)

        sfd._evict_n(sfd.cached_count)
        caller = fm[caller_addr]
        call_edges = [
            (src, dst)
            for src, dst, data in caller.transition_graph.edges(data=True)
            if src.addr == block_addr
            and isinstance(dst, FuncNode)
            and dst.addr == callee_addr
            and data["type"] == "call"
        ]
        assert len(call_edges) == 1


if __name__ == "__main__":
    unittest.main()
