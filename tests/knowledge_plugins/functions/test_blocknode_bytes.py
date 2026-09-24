#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""
BlockNode bytes: user-supplied bytes are stored with the node, every other node reads them from the loader at
addr + delta.
"""

from __future__ import annotations

import gc
import os
import pickle
import tempfile
import unittest

import angr
from angr.angrdb import AngrDB
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function
from angr.rustylib.function_graph import FunctionGraph
from tests.common import bin_location

ARMEL_FAUXWARE = os.path.join(bin_location, "tests", "armel", "fauxware")
FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


def _thumb_nodes(kb):
    return [n for f in kb.functions.values() for n in f.transition_graph if isinstance(n, BlockNode) and n.thumb]


class TestBlockNodeBytes(unittest.TestCase):
    def test_thumb_delta(self):
        proj = angr.Project(ARMEL_FAUXWARE, auto_load_libs=False, cache_limits={"functions": 3})
        proj.analyses.CFGFast()
        thumb_nodes = _thumb_nodes(proj.kb)
        assert thumb_nodes
        # the tiny cache evicted most functions while collecting; their nodes must still reach the loader
        gc.collect()
        assert any(n.owner is None for n in thumb_nodes)
        memory = proj.loader.memory
        for n in thumb_nodes:
            assert n.addr & 1 and n.delta == -1 and not n.manual_bytes
            assert n.bytestr(proj) == memory.load(n.addr - 1, n.size)
        for n in (n for f in proj.kb.functions.values() for n in f.transition_graph if isinstance(n, BlockNode)):
            if not n.thumb:
                assert n.delta == 0
        # spilled and reloaded functions keep delta
        fm = proj.kb.functions._function_map
        assert fm.spilled_count > 0
        thumb_func = next(
            f
            for f in proj.kb.functions.values()
            if any(isinstance(n, BlockNode) and n.thumb for n in f.transition_graph)
        )
        reloaded = Function.parse(thumb_func.serialize(), function_manager=proj.kb.functions, project=proj)
        for n in reloaded.transition_graph:
            if isinstance(n, BlockNode) and n.thumb:
                assert n.delta == -1 and n.bytestr(proj) == memory.load(n.addr - 1, n.size)
        # angrdb round trip
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "armel.adb")
            AngrDB(proj).dump(path)
            proj2 = AngrDB().load(path)
        nodes2 = _thumb_nodes(proj2.kb)
        assert {(n.addr, n.size) for n in nodes2} == {(n.addr, n.size) for n in thumb_nodes}
        assert all(n.delta == -1 and n.bytestr(proj2) == proj2.loader.memory.load(n.addr - 1, n.size) for n in nodes2)
        # pickle
        n = thumb_nodes[0]
        p = pickle.loads(pickle.dumps(n))
        assert p == n and p.delta == -1 and p.thumb and not p.manual_bytes
        assert p.bytestr(proj) == n.bytestr(proj)

    def test_user_supplied_bytes(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False, cache_limits={"functions": 2})
        proj.analyses.CFGFast()
        supplied = BlockNode(0x500000, 4, bytestr=b"\x90" * 4)
        assert supplied.manual_bytes and supplied.bytestr(proj) == b"\x90" * 4
        unmapped = BlockNode(0x500004, 4)
        assert not unmapped.manual_bytes and unmapped.bytestr(proj) is None
        with self.assertRaises(TypeError):
            unmapped.bytestr(None)
        mapped = BlockNode(proj.entry, 8)
        assert not mapped.manual_bytes and mapped.bytestr(proj) == proj.loader.memory.load(proj.entry, 8)

        fm = proj.kb.functions
        func = fm.function(addr=0x500000, create=True)
        assert func is not None
        fm._add_node(0x500000, supplied)
        fm._add_transition_to(0x500000, supplied, unmapped, ins_addr=0x500003, stmt_idx=-2)
        assert unmapped.owner is func and unmapped.bytestr(proj) is None
        assert func._graph.node_bytes(0) == b"\x90" * 4 and func._graph.node_bytes(1) is None

        # spill and reload
        fm.cache_limit = 1
        _ = fm[next(a for a in fm if a != 0x500000)]
        assert 0x500000 in fm._spilled_addrs
        loaded = fm[0x500000]
        node = loaded.code_nodes[0x500000]
        assert node.manual_bytes and node.bytestr(proj) == b"\x90" * 4 and node.delta == 0
        other = loaded.code_nodes[0x500004]
        assert not other.manual_bytes and other.bytestr(proj) is None
        assert {(n.addr, n.manual_bytes) for n in loaded.transition_graph} == {(0x500000, True), (0x500004, False)}
        assert [b.bytes for b in loaded.blocks if b.addr == 0x500000] == [b"\x90" * 4]

        # pickle and angrdb
        p = pickle.loads(pickle.dumps(loaded))
        assert p.code_nodes[0x500000].manual_bytes and p.code_nodes[0x500000].bytestr(proj) == b"\x90" * 4
        assert pickle.loads(pickle.dumps(supplied)).bytestr(proj) == b"\x90" * 4
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "supplied.adb")
            AngrDB(proj).dump(path)
            proj2 = AngrDB().load(path)
        node2 = proj2.kb.functions[0x500000].code_nodes[0x500000]
        assert node2.manual_bytes and node2.bytestr(proj2) == b"\x90" * 4

    def test_only_blob_version_3_is_readable(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        proj.analyses.CFGFast()
        blob = proj.kb.functions["main"]._graph.to_bytes()
        assert blob[0] == 2
        assert FunctionGraph.from_bytes(blob).to_bytes() == blob
        for version in (0, 1, 3, 7):
            with self.assertRaises(ValueError) as cm:
                FunctionGraph.from_bytes(bytes([version]) + blob[1:])
            assert "version" in str(cm.exception)


if __name__ == "__main__":
    unittest.main()
