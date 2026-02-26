#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
import pickle

import angr
from angr.knowledge_plugins.cfg.cfg_node import CFGNode
from angr.knowledge_plugins.cfg.spilling_digraph import SpillingAdjDict, SpillingDiGraph, DirtyDict
from angr.knowledge_plugins.cfg.spilling_cfg import get_block_key

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSpillingAdjDict(unittest.TestCase):
    """Test cases for SpillingAdjDict standalone functionality."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def _make_adj_dict_with_rtdb(self, cache_limit=5, db_batch_size=2):
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        rtdb = proj.kb.rtdb
        return SpillingAdjDict("int", rtdb=rtdb, cache_limit=cache_limit, db_batch_size=db_batch_size), proj

    def test_basic_operations(self):
        """Test basic dict operations on SpillingAdjDict."""
        adj = SpillingAdjDict("int")
        key = (0x400000, 10)
        inner = DirtyDict({(0x400010, 8): {"jumpkind": "Ijk_Boring", "ins_addr": 0x400005, "stmt_idx": 3}}, dirty=True)
        adj[key] = inner

        assert key in adj
        assert len(adj) == 1
        assert adj[key] is inner

        del adj[key]
        assert key not in adj
        assert len(adj) == 0

    def test_lru_eviction(self):
        """Test LRU eviction behavior with small cache limit."""
        adj, _proj = self._make_adj_dict_with_rtdb(cache_limit=3, db_batch_size=2)

        # Insert 6 entries to trigger eviction (cache_limit=3, batch_size=2, triggers at 3+2=5)
        for i in range(6):
            key = (0x400000 + i * 0x10, 8)
            inner = DirtyDict(
                {(0x500000 + i * 0x10, 8): {"jumpkind": "Ijk_Boring", "ins_addr": None, "stmt_idx": None}}, dirty=True
            )
            adj[key] = inner

        # Some entries should be spilled
        assert len(adj._spilled_keys) > 0, "Should have spilled some entries"
        assert len(adj._data) <= 5, "Cache should not exceed limit + batch_size"
        # All entries should still be accessible
        assert len(adj) == 6, "Total count should be preserved"

    def test_spill_and_reload(self):
        """Test that spilled entries can be loaded back correctly."""
        adj, _proj = self._make_adj_dict_with_rtdb(cache_limit=2, db_batch_size=1)

        keys = []
        for i in range(5):
            key = (0x400000 + i * 0x10, 8)
            inner = {
                (0x500000 + i * 0x10, 8): {
                    "jumpkind": "Ijk_Boring",
                    "ins_addr": 0x400000 + i * 0x10 + 5,
                    "stmt_idx": i,
                }
            }
            adj[key] = DirtyDict(inner, dirty=True)
            keys.append(key)

        # Access first key (which was likely evicted)
        first_key = keys[0]
        loaded_inner = adj[first_key]
        assert loaded_inner is not None
        dst_key = (0x500000, 8)
        assert dst_key in loaded_inner
        assert loaded_inner[dst_key]["jumpkind"] == "Ijk_Boring"
        assert loaded_inner[dst_key]["ins_addr"] == 0x400005
        assert loaded_inner[dst_key]["stmt_idx"] == 0

    def test_edge_data_serialization_roundtrip(self):
        """Test that edge data survives serialization/deserialization."""
        original = {"jumpkind": "Ijk_Call", "ins_addr": 0xDEADBEEF, "stmt_idx": 42}
        serialized = SpillingAdjDict._serialize_edge_data(original)
        deserialized = SpillingAdjDict._deserialize_edge_data(serialized)

        assert deserialized["jumpkind"] == "Ijk_Call"
        assert deserialized["ins_addr"] == 0xDEADBEEF
        assert deserialized["stmt_idx"] == 42

    def test_edge_data_serialization_none_values(self):
        """Test serialization handles None values for ins_addr and stmt_idx."""
        original = {"jumpkind": "Ijk_Boring", "ins_addr": None, "stmt_idx": None}
        serialized = SpillingAdjDict._serialize_edge_data(original)
        deserialized = SpillingAdjDict._deserialize_edge_data(serialized)

        assert deserialized["jumpkind"] == "Ijk_Boring"
        assert deserialized["ins_addr"] is None
        assert deserialized["stmt_idx"] is None

    def test_inner_dict_serialization_roundtrip(self):
        """Test that inner dicts survive serialization/deserialization."""
        d = SpillingAdjDict("int")
        inner = {
            (0x400010, 8): {"jumpkind": "Ijk_Boring", "ins_addr": 0x400005, "stmt_idx": 3},
            (0x400020, 16): {"jumpkind": "Ijk_Call", "ins_addr": None, "stmt_idx": None},
        }
        serialized = d._serialize_inner_dict(DirtyDict(inner, dirty=True))
        deserialized = d._deserialize_inner_dict(serialized)

        assert len(deserialized) == 2
        assert (0x400010, 8) in deserialized
        assert deserialized[(0x400010, 8)]["jumpkind"] == "Ijk_Boring"
        assert deserialized[(0x400010, 8)]["ins_addr"] == 0x400005
        assert deserialized[(0x400010, 8)]["stmt_idx"] == 3
        assert (0x400020, 16) in deserialized
        assert deserialized[(0x400020, 16)]["jumpkind"] == "Ijk_Call"

    def test_load_all_spilled(self):
        """Test load_all_spilled brings everything back to memory."""
        adj, _proj = self._make_adj_dict_with_rtdb(cache_limit=2, db_batch_size=1)

        for i in range(5):
            key = (0x400000 + i * 0x10, 8)
            inner = {(0x500000 + i * 0x10, 8): {"jumpkind": "Ijk_Boring", "ins_addr": None, "stmt_idx": None}}
            adj[key] = DirtyDict(inner, dirty=True)

        assert len(adj._spilled_keys) > 0
        adj.load_all_spilled()
        assert len(adj._spilled_keys) == 0
        assert len(adj._data) == 5

    def test_iteration(self):
        """Test iterating over SpillingAdjDict."""
        adj, _proj = self._make_adj_dict_with_rtdb(cache_limit=2, db_batch_size=1)

        expected_keys = set()
        for i in range(5):
            key = (0x400000 + i * 0x10, 8)
            inner = {(0x500000 + i * 0x10, 8): {"jumpkind": "Ijk_Boring", "ins_addr": None, "stmt_idx": None}}
            adj[key] = DirtyDict(inner, dirty=True)
            expected_keys.add(key)

        # Iterate over all keys
        seen_keys = set()
        for key in adj:
            seen_keys.add(key)
        assert seen_keys == expected_keys

    def test_pickling(self):
        """Test pickling support."""
        adj, _proj = self._make_adj_dict_with_rtdb(cache_limit=2, db_batch_size=1)

        for i in range(5):
            key = (0x400000 + i * 0x10, 8)
            inner = {(0x500000 + i * 0x10, 8): {"jumpkind": "Ijk_Boring", "ins_addr": None, "stmt_idx": None}}
            adj[key] = DirtyDict(inner, dirty=True)

        data = pickle.dumps(adj)
        restored = pickle.loads(data)

        assert len(restored) == 5
        for i in range(5):
            key = (0x400000 + i * 0x10, 8)
            assert key in restored


class TestSpillingDiGraph(unittest.TestCase):
    """Test cases for SpillingDiGraph."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_graph_creation(self):
        """Test that SpillingDiGraph creates SpillingAdjDict for adjacency."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        g = SpillingDiGraph(rtdb=proj.kb.rtdb)

        assert isinstance(g._adj, SpillingAdjDict)
        assert isinstance(g._pred, SpillingAdjDict)

    def test_add_node_and_edge(self):
        """Test basic node and edge operations."""
        g = SpillingDiGraph()

        g.add_node("a")
        g.add_node("b")
        g.add_edge("a", "b", jumpkind="Ijk_Boring", ins_addr=0x400000, stmt_idx=1)

        assert "a" in g
        assert "b" in g
        assert g.has_edge("a", "b")
        assert g["a"]["b"]["jumpkind"] == "Ijk_Boring"

    def test_adjlist_outer_dict_factory_override(self):
        """Test that adjlist_outer_dict_factory returns SpillingAdjDict factory."""
        g = SpillingDiGraph()
        factory = g.adjlist_outer_dict_factory
        result = factory()
        assert isinstance(result, SpillingAdjDict)


class TestSpillingDiGraphIntegration(unittest.TestCase):
    """Integration tests for SpillingDiGraph with SpillingCFG."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_cfg_uses_spilling_digraph(self):
        """Test that SpillingCFG uses SpillingDiGraph internally."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        graph = cfg.model.graph
        assert isinstance(graph._graph, SpillingDiGraph), "SpillingCFG._graph should be a SpillingDiGraph"
        assert isinstance(graph._graph._adj, SpillingAdjDict), "_adj should be SpillingAdjDict"
        assert isinstance(graph._graph._pred, SpillingAdjDict), "_pred should be SpillingAdjDict"

    def test_edges_data_preserved(self):
        """Test that edge data is preserved through SpillingDiGraph."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for _, _, data in cfg.model.graph.edges(data=True):
            assert isinstance(data, dict)
            assert "jumpkind" in data
            break

    def test_graph_traversal(self):
        """Test successors/predecessors work correctly."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for node in cfg.model.graph.nodes():
            succs = list(cfg.model.graph.successors(node))
            if succs:
                preds = list(cfg.model.graph.predecessors(succs[0]))
                assert node in preds
                break

    def test_edge_spilling_with_small_cache(self):
        """Test that edge spilling works with a small cache limit."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        graph = cfg.model.graph
        total_edges = graph.number_of_edges()

        if total_edges <= 5:
            self.skipTest("Not enough edges to test spilling")

        # Get the underlying SpillingDiGraph and reduce its edge cache limits
        digraph = graph._graph
        adj = digraph._adj
        pred = digraph._pred

        # Set a very small cache limit to force edge spilling
        adj._cache_limit = 3
        adj._db_batch_size = 1
        pred._cache_limit = 3
        pred._db_batch_size = 1

        # Evict all to LMDB, then reload
        adj.evict_all_cached()
        pred.evict_all_cached()

        assert adj._spilled_keys, "adj should have spilled entries"
        assert pred._spilled_keys, "pred should have spilled entries"

        # Verify all edges are still accessible
        edge_count = 0
        for src, dst, data in graph.edges(data=True):
            assert isinstance(src, CFGNode)
            assert isinstance(dst, CFGNode)
            assert isinstance(data, dict)
            assert "jumpkind" in data
            edge_count += 1

        assert edge_count == total_edges, "All edges should be accessible after spilling"

    def test_edge_data_survives_spilling(self):
        """Test that specific edge attributes survive spill and reload."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        graph = cfg.model.graph

        # Collect original edge data
        original_edges = {}
        for src, dst, data in graph.edges(data=True):
            src_key = get_block_key(src)
            dst_key = get_block_key(dst)
            original_edges[(src_key, dst_key)] = dict(data)

        if len(original_edges) <= 5:
            self.skipTest("Not enough edges to test")

        # Force spilling
        digraph = graph._graph
        digraph._adj._cache_limit = 2
        digraph._adj._db_batch_size = 1
        digraph._pred._cache_limit = 2
        digraph._pred._db_batch_size = 1
        digraph._adj.evict_all_cached()
        digraph._pred.evict_all_cached()

        # Load back and compare
        for src, dst, data in graph.edges(data=True):
            src_key = get_block_key(src)
            dst_key = get_block_key(dst)
            orig = original_edges.get((src_key, dst_key))
            assert orig is not None, f"Edge ({src_key}, {dst_key}) not found in original"
            # After roundtrip, edge data is normalized to always include all three keys.
            # Use .get() to safely compare (original may not have ins_addr/stmt_idx).
            assert data["jumpkind"] == orig.get("jumpkind"), (
                f"jumpkind mismatch: {data['jumpkind']} != {orig.get('jumpkind')}"
            )
            assert data.get("ins_addr") == orig.get("ins_addr"), (
                f"ins_addr mismatch: {data.get('ins_addr')} != {orig.get('ins_addr')}"
            )
            assert data.get("stmt_idx") == orig.get("stmt_idx"), (
                f"stmt_idx mismatch: {data.get('stmt_idx')} != {orig.get('stmt_idx')}"
            )


if __name__ == "__main__":
    unittest.main()
