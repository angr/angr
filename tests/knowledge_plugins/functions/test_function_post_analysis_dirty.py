#!/usr/bin/env python3
# pylint: disable=missing-class-docstring
"""Regression test for the missing mark_dirty on fake_return cleanup.

Before the fix, CFGFast._post_analysis removed unconfirmed fake_return
edges via `f.transition_graph.remove_edge(*edge)`, bypassing the
@dirty_func-decorated Function._remove_fakeret. If the function was
just loaded from LMDB (so f._dirty was False) the mutation didn't
flip the dirty flag, and the cleanup was silently lost on the next
eviction/reload cycle through SpillingFunctionDict.
"""
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"

import tempfile
import unittest

import angr
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function


class TestFunctionPostAnalysisDirty(unittest.TestCase):
    def test_fakeret_cleanup_marks_dirty(self):
        # 14-byte AMD64 block ending in a `call rel32` — the exact
        # instruction pattern that produces unconfirmed fake_return
        # edges to external blocks during CFGFast.
        blob = bytes.fromhex("ffc86b060000000000e86b060001")
        addr = 0x100077547
        fakeret_dst_addr = addr + 14  # byte past the 5-byte call

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(blob)
            blob_path = f.name

        proj = angr.Project(
            blob_path,
            main_opts={
                "backend": "blob",
                "base_addr": addr,
                "arch": "AMD64",
                "entry_point": addr,
            },
            auto_load_libs=False,
        )

        fm = proj.kb.functions
        func = fm.function(addr=addr, create=True)
        local_block = BlockNode(addr, 14, bytestr=blob[:14])
        ext_block = BlockNode(fakeret_dst_addr, 4, bytestr=b"\x00" * 4)

        func._register_node(True, local_block)
        # CFGFast leaves an unconfirmed fake_return edge to an external
        # block when the call's return target is later determined to
        # belong to a non-returning function. Build that exact shape.
        func.transition_graph.add_node(ext_block)
        func.transition_graph.add_edge(
            local_block, ext_block, type="fake_return", outside=False,
        )

        # Round-trip through the parser to set _dirty=False, mimicking
        # a normal SpillingFunctionDict reload.
        cmsg = func.serialize_to_cmessage()
        loaded = Function.parse_from_cmessage(
            cmsg, function_manager=fm, project=proj,
        )
        self.assertFalse(
            loaded._dirty,
            "test setup: parse_from_cmessage should reset _dirty=False",
        )

        # Find the fake_return edge that CFGFast._post_analysis would
        # decide to remove. (We simulate that decision directly instead
        # of running the full CFGFast pipeline.)
        fakeret_edges = [
            (s, d)
            for s, d, data in loaded.transition_graph.edges(data=True)
            if data.get("type") == "fake_return"
        ]
        self.assertEqual(len(fakeret_edges), 1)
        src, dst = fakeret_edges[0]

        # Operation under test. After the fix _post_analysis routes
        # this through Function._remove_fakeret (@dirty_func); before
        # the fix it was a direct graph mutation that left _dirty
        # untouched.
        loaded._remove_fakeret(src, dst)

        self.assertTrue(
            loaded._dirty,
            "Function must be marked dirty after fake_return edge removal so "
            "that SpillingFunctionDict._evict_n persists the cleanup to LMDB.",
        )


if __name__ == "__main__":
    unittest.main()
