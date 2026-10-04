# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
import unittest

from angr.analyses import Decompiler
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from tests.common import bin_location, load_project_with_scoped_cfg


class TestRewriteCcalls(unittest.TestCase):
    def test_rewritten_blocks_are_node_keyed_and_marked_simplified(self):
        # rotl64: `rol rdx, cl` keeps a surviving amd64g_calculate_rflags_all ccall
        bin_path = os.path.join(bin_location, "tests", "x86_64", "dir_gcc_-O0")
        addr = 0x417471
        proj, cfg = load_project_with_scoped_cfg(bin_path, addr, window=0x40, expand_call_tree=False)

        pending: dict[int, set[tuple[int, int | None]]] = {}
        checked: list[set[tuple[int, int | None]]] = []
        orig_rewrite = AILSimplifier._rewrite_ccalls
        orig_rebuild = AILSimplifier._rebuild_func_graph

        def _rewrite_ccalls(self: AILSimplifier) -> bool:
            r = orig_rewrite(self)
            if r:
                node_ids = {id(n) for n in self.func_graph}
                for key in self.blocks:
                    assert id(key) in node_ids, f"ccall rewrite keyed {key!r} by a block that is not a graph node"
                keys = {(b.addr, b.idx) for b in self.blocks.values()}
                # an earlier step may have marked these blocks already; the rebuild must mark them on its own
                self.simplified_blocks -= keys
                pending[id(self)] = keys
            return r

        def _rebuild_func_graph(self: AILSimplifier) -> None:
            orig_rebuild(self)
            keys = pending.pop(id(self), None)
            if keys is not None:
                assert keys <= self.simplified_blocks, "ccall-rewritten blocks missing from simplified_blocks"
                checked.append(keys)

        AILSimplifier._rewrite_ccalls = _rewrite_ccalls
        AILSimplifier._rebuild_func_graph = _rebuild_func_graph
        try:
            dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[addr], cfg=cfg.model)
        finally:
            AILSimplifier._rewrite_ccalls = orig_rewrite
            AILSimplifier._rebuild_func_graph = orig_rebuild
        assert dec.codegen is not None
        assert checked, "expected at least one ccall rewrite in rotl64"


if __name__ == "__main__":
    unittest.main()
