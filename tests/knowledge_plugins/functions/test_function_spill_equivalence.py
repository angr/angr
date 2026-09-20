#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""
Functions that were spilled to LMDB and reloaded must be indistinguishable from functions that were never evicted,
both while CFGFast is running with a small function cache and after evicting a finished knowledge base.
"""

from __future__ import annotations

import os
import tempfile
import unittest

import angr
from angr.angrdb import AngrDB
from angr.codenode import BlockNode, FuncNode, HookNode, SyscallNode
from angr.knowledge_plugins.functions.function_manager import SpillingFunctionDict
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _node_key(node):
    if isinstance(node, SyscallNode):
        kind = "SyscallNode"
    elif isinstance(node, HookNode):
        kind = "HookNode"
    elif isinstance(node, FuncNode):
        kind = "FuncNode"
    elif isinstance(node, BlockNode):
        kind = "BlockNode"
    else:
        kind = type(node).__name__
    return (kind, node.addr, node.size, node.thumb)


def _func_digest(func) -> dict:
    graph = func.transition_graph
    return {
        "name": func.name,
        "blocks": sorted(func.block_addrs_set),
        "block_sizes": sorted(func._block_sizes.items()),
        "nodes": sorted(_node_key(n) for n in graph.nodes()),
        "edges": sorted(
            (_node_key(src), _node_key(dst), tuple(sorted((k, str(v)) for k, v in data.items())))
            for src, dst, data in graph.edges(data=True)
        ),
        "endpoints": {k: sorted(_node_key(n) for n in v) for k, v in func.endpoints_with_type.items()},
        "ret_sites": sorted(_node_key(n) for n in func.ret_sites),
        "retout_sites": sorted(_node_key(n) for n in func.retout_sites),
        "jumpout_sites": sorted(_node_key(n) for n in func.jumpout_sites),
        "callout_sites": sorted(_node_key(n) for n in func.callout_sites),
        "has_return": func.has_return,
        "returning": func.returning,
        "startpoint": _node_key(func.startpoint) if func.startpoint is not None else None,
        "call_sites": sorted(func._call_sites.items()),
        "is_plt": func.is_plt,
        "is_syscall": func.is_syscall,
        "is_simprocedure": func.is_simprocedure,
        "alignment": func.is_alignment,
        "info": dict(func.info),
        "previous_names": list(func.previous_names),
    }


def _kb_digest(kb) -> dict[int, dict]:
    return {func.addr: _func_digest(func) for func in kb.functions.values()}


class TestFunctionSpillEquivalence(unittest.TestCase):
    def _assert_kb_digests_equal(self, expected: dict, actual: dict):
        self.assertEqual(set(expected), set(actual))
        for addr, digest in expected.items():
            self.assertEqual(digest, actual[addr], f"function {addr:#x} differs")

    def test_cfg_with_spilling_matches_cfg_without_spilling(self):
        path = os.path.join(test_location, "x86_64", "true")
        proj_nospill = angr.Project(path, auto_load_libs=False, cache_limits={"functions": None})
        proj_nospill.analyses.CFGFast(normalize=False)
        expected = _kb_digest(proj_nospill.kb)

        proj_spill = angr.Project(path, auto_load_libs=False, cache_limits={"functions": 5})
        proj_spill.analyses.CFGFast(normalize=False)
        function_map = proj_spill.kb.functions._function_map
        assert isinstance(function_map, SpillingFunctionDict)
        self.assertGreater(function_map.spilled_count, 0)

        self._assert_kb_digests_equal(expected, _kb_digest(proj_spill.kb))

        # angrdb round trip of the spilled knowledge base
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "true.adb")
            AngrDB(proj_spill).dump(db_path)
            proj_loaded = AngrDB().load(db_path)
        self._assert_kb_digests_equal(expected, _kb_digest(proj_loaded.kb))

    def test_evicting_finished_kb_is_lossless(self):
        proj = angr.Project(
            os.path.join(test_location, "armel", "fauxware"), auto_load_libs=False, cache_limits={"functions": None}
        )
        proj.analyses.CFGFast(normalize=False)
        expected = _kb_digest(proj.kb)
        assert any(n[3] for d in expected.values() for n in d["nodes"])  # thumb blocks
        assert any(d["startpoint"][0] == "HookNode" for d in expected.values())

        fm = proj.kb.functions
        fm.cache_limit = 2  # converts to a SpillingFunctionDict and evicts everything but two functions
        function_map = fm._function_map
        assert isinstance(function_map, SpillingFunctionDict)
        self.assertLessEqual(function_map.cached_count, 2)
        self.assertGreater(function_map.spilled_count, 0)

        self._assert_kb_digests_equal(expected, _kb_digest(proj.kb))


if __name__ == "__main__":
    unittest.main()
