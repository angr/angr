#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
"""Test cases for SpillingCFG: CFGNode views over the node records of the Rust store, and segment paging."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import gc
import os
import pickle
import unittest

import angr
from angr.knowledge_plugins.cfg.cfg_model import CFGModel
from angr.knowledge_plugins.cfg.cfg_node import CFGENode, CFGNode
from angr.knowledge_plugins.cfg.spilling_cfg import SpillingCFG, get_block_key
from angr.rustylib.cfg_graph import BYTES_LOADER, BYTES_MANUAL, BYTES_NONE
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


def _node_rec(n: CFGNode) -> tuple:
    return (
        n.addr,
        n.size,
        n.block_id,
        n.name,
        n.function_address,
        n.no_ret,
        n.thumb,
        n.is_syscall,
        n.simprocedure_name,
        n.byte_string,
        tuple(n.instruction_addrs),
    )


def _edge_recs(m: CFGModel) -> list[tuple]:
    return sorted(
        (s.addr, s.size, d.addr, d.size, data["jumpkind"], data.get("ins_addr"), data.get("stmt_idx"))
        for s, d, data in m.graph.edges(data=True)
    )


class TestCFGNodeViews(unittest.TestCase):
    """CFGNode objects of an integer-keyed graph are views over the store's node records."""

    def test_fields_live_in_the_store(self):
        g = SpillingCFG()
        node = CFGNode(0x1000, 8, None, function_address=0x1000, instruction_addrs=[0x1000, 0x1003], no_ret=None)
        g.add_node(node)
        idx = node._id
        assert node._store is g._graph and idx is not None
        assert node._function_address is None  # the object no longer holds the fields

        node.function_address = 0x2000
        node.no_ret = True
        node.instruction_addrs = [0x1000, 0x1004]
        func, base, _, _, _, no_ret, mode, manual, _, _ = g._graph.node_fields(idx)
        assert (func, base, no_ret, mode, manual) == (0x2000, 0x1000, True, BYTES_NONE, None)
        assert node.dirty

        # repeated lookups return the same object; the record is the truth for a fresh view
        assert next(g.nodes_by_addr(0x1000)) is node
        g._keys.detach_all()
        fresh = next(g.nodes_by_addr(0x1000))
        assert fresh is not node and fresh == node and hash(fresh) == hash(node)
        assert (fresh.function_address, fresh.no_ret, list(fresh.instruction_addrs)) == (0x2000, True, [0x1000, 0x1004])
        # the detached object kept a snapshot
        assert node._store is None and node.function_address == 0x2000

        with self.assertRaises(TypeError):
            g.add_node(CFGENode(0x2000, 4, None, callstack_key=(None, None), block_id=0x2000))

    def test_remove_and_overwrite_detach_views(self):
        g = SpillingCFG()
        a = CFGNode(0x1000, 4, None, function_address=0x1000, byte_string=b"\x90" * 4)
        b = CFGNode(0x1004, 4, None, function_address=0x1000)
        g.add_edge(a, b, jumpkind="Ijk_Boring", ins_addr=0x1003, stmt_idx=-2)
        old_id = a._id

        g.remove_node(a)
        assert a._store is None and a.function_address == 0x1000 and a.byte_string == b"\x90" * 4
        # the freed id is reused by the next node of that segment; the old object is unaffected
        c = CFGNode(0x1000, 4, None, function_address=0x3000)
        g.add_node(c)
        assert c._id == old_id and a.function_address == 0x1000 and c.function_address == 0x3000

        # adding a detached node whose key exists overwrites the record and detaches the previous view
        d = CFGNode(0x1000, 4, None, function_address=0x4000, simprocedure_name=None)
        g.add_node(d)
        assert c._store is None and c.function_address == 0x3000
        assert d._id == old_id and next(g.nodes_by_addr(0x1000)) is d and d.function_address == 0x4000
        assert list(g.successors(d)) == []

    def test_from_networkx_and_clear_detach(self):
        g = SpillingCFG()
        a = CFGNode(0x1000, 4, None, function_address=0x1000)
        g.add_node(a)
        nxg = g.to_networkx()
        g.from_networkx(nxg)
        # a's record was dropped and rebuilt from a's own (snapshotted) fields
        assert next(g.nodes_by_addr(0x1000)) is a and a.function_address == 0x1000

    def test_byte_string_modes_and_names(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        model = proj.kb.cfgs.new_model("test")
        main = proj.loader.find_symbol("main").rebased_addr
        block = proj.factory.block(main)
        same = CFGNode(main, block.size, model, byte_string=block.bytes, function_address=main, block_id=main)
        other = CFGNode(main + 0x100, 2, model, byte_string=b"\xcc\xcc", function_address=main, block_id=main + 0x100)
        none = CFGNode(main + 0x200, 2, model, function_address=main, block_id=main + 0x200)
        for n in (same, other, none):
            model.graph.add_node(n)
        store = model.graph._graph
        assert store.node_bytes(same._id)[0] == BYTES_LOADER  # not stored
        assert store.node_bytes(other._id) == (BYTES_MANUAL, b"\xcc\xcc")
        assert store.node_bytes(none._id) == (BYTES_NONE, None)
        assert (same.byte_string, other.byte_string, none.byte_string) == (block.bytes, b"\xcc\xcc", None)

        # names resolve lazily and are written back to the record
        assert store.node_name(other._id) is None
        assert same.name == "main" and other.name == "main+0x100"
        assert store.node_name(other._id) == "main+0x100"
        # a new function address resets the name
        other.function_address = None
        assert store.node_name(other._id) is None

    def test_views_are_released(self):
        g = SpillingCFG()
        n = g._keys.RING_SIZE + 64
        for i in range(n):
            g.add_node(CFGNode(0x1000 + 4 * i, 4, None, block_id=0x1000 + 4 * i))
        gc.collect()
        assert len(g._keys._cache) <= g._keys.RING_SIZE
        assert [node.addr for node in g.nodes()] == [0x1000 + 4 * i for i in range(n)]


class TestSegmentPaging(unittest.TestCase):
    """Node records are paged with the graph segments."""

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.ref = proj.analyses.CFGFast(normalize=True).model

    def test_default_resident(self):
        assert not self.ref.graph.paged and self.ref.graph.segment_budget is None

    def test_paged_cfgfast_matches_resident(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False, cache_limits={"cfg_segment_bytes": 1})
        model = proj.analyses.CFGFast(normalize=True).model
        graph = model.graph
        assert graph.paged and graph.segment_stats()["evictions"] > 0
        assert sorted(_node_rec(n) for n in graph.nodes()) == sorted(_node_rec(n) for n in self.ref.graph.nodes())
        assert _edge_recs(model) == _edge_recs(self.ref)

        # a mutation through a view survives the eviction of its segment
        node = model.get_any_node(proj.entry)
        node.function_address = 0x1234
        graph._graph.evict_all()
        assert graph.segment_stats()["resident_segments"] == 0
        assert node.function_address == 0x1234
        graph._keys.detach_all()
        assert model.get_any_node(proj.entry).function_address == 0x1234

    def test_copy(self):
        copied = self.ref.copy()
        assert len(copied.graph) == len(self.ref.graph)
        assert sorted(_node_rec(n) for n in copied.graph.nodes()) == sorted(
            _node_rec(n) for n in self.ref.graph.nodes()
        )
        # the copy has its own records
        node = next(iter(copied.graph.nodes()))
        node.function_address = 0x1234
        assert self.ref.graph.get_node_by_key(get_block_key(node)).function_address != 0x1234

    def test_pickle_roundtrip_paged(self):
        """Round-tripping a paged CFG through pickle must not lose nodes, node fields or edges (#6529)."""
        proj = angr.Project(FAUXWARE, auto_load_libs=False, cache_limits={"cfg_segment_bytes": 1})
        model = proj.analyses.CFGFast(normalize=True).model
        # resolved names are written back to the records (and pickled with them)
        expected = sorted(_node_rec(n) for n in model.graph.nodes())
        model.graph._graph.evict_all()
        restored = pickle.loads(pickle.dumps(model))
        # without a project, loader bytes cannot be read back
        assert sorted(_node_rec(n)[:9] for n in restored.graph.nodes()) == [r[:9] for r in expected]
        assert _edge_recs(restored) == _edge_recs(model)


class TestCFGModelIntegration(unittest.TestCase):
    """Integration tests for CFGModel with SpillingCFG."""

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.model = proj.analyses.CFGFast().model

    def test_nodes_mapping(self):
        model = self.model
        nodes = model._nodes
        assert len(nodes) == len(model.graph) > 0
        keys = list(nodes)
        assert len(keys) == len(nodes)
        for key in keys[:3]:
            assert key in nodes and get_block_key(nodes[key]) == key
        assert nodes.get((0xDEAD, 1)) is None

    def test_graph_queries(self):
        graph = self.model.graph
        for src, dst, data in graph.edges(data=True):
            assert isinstance(src, CFGNode) and isinstance(dst, CFGNode) and "jumpkind" in data
            assert graph.has_edge(src, dst) and graph[src][dst] == data
            assert src in list(graph.predecessors(dst)) and dst in list(graph.successors(src))
            assert (dst, data["jumpkind"]) in graph.successors_and_jumpkinds(src)
            break

    def test_get_node(self):
        model = self.model
        for block_id in model._blockid_to_blockkey:
            node = model.get_node(block_id)
            assert node is not None and node.block_id == block_id
            break

    def test_lookup_outside_u64_range(self):
        """Addresses outside the u64 range (e.g., a negative loader entry) must miss, not raise."""
        model = self.model
        for addr in (-1, -2244608, 1 << 64):
            assert model.get_any_node(addr, force_fastpath=True) is None
            assert model.get_any_node(addr, anyaddr=True) is None
            assert not model.graph.has_node_addr(addr)
            assert list(model.graph.nodes_by_addr(addr)) == []

    def test_get_any_node(self):
        model = self.model
        for node in model.graph.nodes():
            found = model.get_any_node(node.addr)
            assert found is not None and found.addr == node.addr
            break


if __name__ == "__main__":
    unittest.main()
