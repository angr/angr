#!/usr/bin/env python3
# pylint: disable=missing-class-docstring
"""Regression test for serialize/parse round-trip non-idempotence
when a Function has a fake_return edge whose destination is external
(in cmsg.external_blocks at save time) but whose edge attribute
outside=False.

Before the fix, parse_from_cmessage's call-edge handler trusted the
saved edge attribute and called _call_to(return_to_outside=False),
which made _call_to register the destination as a local block via
_register_node. Each roundtrip added one entry to
_local_block_addrs.

This shape arises organically when CFGFast calls
kb.functions._add_fakeret_to(..., confirmed=None) -- the underlying
Function._fakeret_to(confirmed=None) adds the edge with
outside=False but does NOT call _register_node for the to_node
(the `if confirmed:` branch is skipped). At save the dst goes to
cmsg.external_blocks; the edge keeps is_outside=False; the loader
then disagrees.
"""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"

import tempfile
import unittest

import angr
from angr.codenode import BlockNode, FuncNode
from angr.knowledge_plugins.functions.function import Function


class TestFunctionParserFakeret(unittest.TestCase):
    def test_serialize_parse_roundtrip_with_external_fakeret(self):
        blob = bytes.fromhex("ffc86b060000000000e86b060001")
        addr = 0x100077547
        fakeret_dst_addr = addr + 14
        call_dst_addr = 0x101077BC0

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
        assert func is not None
        local_block = BlockNode(addr, 14, bytestr=blob[:14])
        ext_block = BlockNode(fakeret_dst_addr, 4, bytestr=b"\x00" * 4)

        func._register_node(True, local_block)

        # Synthesize the call + fake_return edge pair that CFGFast can
        # leave behind via _add_fakeret_to(confirmed=None).
        call_target = FuncNode(call_dst_addr)
        func.transition_graph.add_node(call_target)
        func.transition_graph.add_edge(
            local_block,
            call_target,
            type="call",
            outside=False,
            ins_addr=addr + 9,
            stmt_idx=None,
        )
        func.transition_graph.add_node(ext_block)
        func.transition_graph.add_edge(
            local_block,
            ext_block,
            type="fake_return",
            outside=False,
            confirmed=True,
            ins_addr=addr + 9,
            stmt_idx=None,
        )

        pre = set(func._local_block_addrs)
        cmsg = func.serialize_to_cmessage()

        # Sanity: cmsg shape that exposes the bug.
        self.assertEqual([b.ea for b in cmsg.blocks], [addr])
        fakeret_edges = [e for e in cmsg.graph.edges if e.dst_ea == fakeret_dst_addr]
        self.assertEqual(len(fakeret_edges), 1)
        self.assertFalse(
            bool(fakeret_edges[0].is_outside),
            "test setup: edge must have is_outside=False",
        )

        loaded = Function.parse_from_cmessage(
            cmsg,
            function_manager=fm,
            project=proj,
        )
        post = set(loaded._local_block_addrs)
        self.assertEqual(
            pre,
            post,
            f"round-trip is not idempotent: pre={sorted(hex(a) for a in pre)} post={sorted(hex(a) for a in post)}",
        )


if __name__ == "__main__":
    unittest.main()
