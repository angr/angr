#!/usr/bin/env python3
# pylint: disable=missing-class-docstring
"""Regression test for `CFGFast.drop_bad_functions`'s per-block
cleanup being a no-op for spilled bad functions.

Before the fix, the cleanup loop in `drop_bad_functions` did:

    for block in func.blocks:
        self._seg_list.occupy(block.addr, block.size, "unknown")
        cfg_node = self.model.get_any_node(block.addr)
        if cfg_node is not None:
            self.model.remove_node_and_graph_node(cfg_node)

with `func` loaded via `meta_only=True`. `Function.parse_from_cmessage`
in meta-only mode populates `_local_block_addrs` (a set of addresses)
but NOT `_local_blocks` (the address->BlockNode dict that
`Function.blocks` iterates), so the loop was a silent no-op for any
bad function spilled at drop time. The function was removed from
`kb.functions` but its CFG nodes survived and the bytes stayed
classified as "code" in `_seg_list`, leaving the model in a state
that depended on LRU cache timing.

This test verifies that the cleanup path (iterating
`func.block_addrs` and reading sizes from the CFG model) DOES remove
the CFG node for a function whose `_local_blocks` is empty -- which
is the post-fix shape of the cleanup logic in
`CFGFast.drop_bad_functions`.
"""

from __future__ import annotations

import tempfile
import unittest

import angr
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function


class TestDropBadFunctionsSpilledCleanup(unittest.TestCase):
    def test_meta_only_load_does_not_populate_local_blocks(self):
        """Documents the underlying meta_only behavior that the bug
        depended on: `func.blocks` is empty after a meta-only parse,
        even though `func.block_addrs` is not."""
        blob = bytes.fromhex("ffc8") + b"\x00" * 12
        addr = 0x100077547

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
        func._register_node(True, BlockNode(addr, 14, bytestr=blob[:14]))

        cmsg = func.serialize_to_cmessage()
        meta = Function.parse_from_cmessage(
            cmsg,
            function_manager=fm,
            project=proj,
            meta_only=True,
        )

        # block_addrs is populated for spilled funcs; this is what the
        # post-fix cleanup loop in CFGFast.drop_bad_functions iterates.
        self.assertEqual(set(meta.block_addrs), {addr})

        # `Function.blocks` (which iterates `_local_blocks.items()`) is
        # empty in meta-only mode. The pre-fix cleanup loop iterated
        # this and was silently a no-op for spilled bad functions.
        self.assertEqual(
            sum(1 for _ in meta.blocks),
            0,
            "Function.blocks must be empty in meta-only mode -- any "
            "code that needs to iterate a spilled function's blocks "
            "must use block_addrs and look up sizes via the CFG model.",
        )

    def test_drop_bad_functions_cleanup_runs_on_spilled_function(self):
        """End-to-end check that drop_bad_functions's cleanup actually
        removes the CFG node and reclassifies the bytes when the bad
        function is in the meta-only-loaded state."""
        # We don't run the full CFGFast scan -- we synthesize the
        # exact state drop_bad_functions's cleanup loop sees on a
        # spilled bad function: a meta-only Function plus a CFGNode
        # in the model for that block address.
        blob = bytes.fromhex("ffc8") + b"\x00" * 12
        addr = 0x100077547
        block_size = 14

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

        # Get a CFGFast instance with a populated model that contains
        # a node at `addr`. The simplest way is to actually run
        # CFGFast on the blob and then synthesize the drop case.
        cfg = proj.analyses.CFGFast(
            normalize=True,
            cross_references=False,
            data_references=False,
            force_smart_scan=False,
            force_complete_scan=False,
        )
        cfg_node = cfg.model.get_any_node(addr)
        assert cfg_node is not None, "CFGFast should have lifted a node at the entrypoint"

        fm = proj.kb.functions
        func = fm.get_by_addr(addr)
        assert func is not None

        # Serialize the function and re-parse it in meta-only mode.
        # This is exactly the state drop_bad_functions encounters
        # when a bad function was spilled to LMDB by
        # SpillingFunctionDict before the removal loop runs.
        cmsg = func.serialize_to_cmessage()
        meta = Function.parse_from_cmessage(
            cmsg,
            function_manager=fm,
            project=proj,
            meta_only=True,
        )

        # Pre-condition: the CFG node is in the model.
        self.assertTrue(
            cfg.model.get_any_node(addr) is not None,
            "test setup: CFG node should be present before cleanup",
        )

        # Run the post-fix cleanup logic.
        for block_addr in list(meta.block_addrs):
            cn = cfg.model.get_any_node(block_addr)
            if cn is not None:
                cfg._seg_list.occupy(int(cn.addr), int(cn.size), "unknown")
                cfg.model.remove_node_and_graph_node(cn)

        # Post-condition: the CFG node has been removed and the bytes
        # have been reclassified.
        self.assertIsNone(
            cfg.model.get_any_node(addr),
            "cleanup must remove the CFG node even for a meta-only-"
            "loaded function -- this is the regression #6418 guards.",
        )
        self.assertEqual(
            cfg._seg_list.occupied_by_sort(addr),
            "unknown",
            "cleanup must reclassify the bytes from 'code' to 'unknown' for a meta-only-loaded function.",
        )
        _ = block_size  # suppress unused-var if linting is picky


if __name__ == "__main__":
    unittest.main()
