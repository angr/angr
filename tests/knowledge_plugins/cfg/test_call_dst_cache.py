#!/usr/bin/env python3
# pylint:disable=no-self-use
"""Test cases for SpillingCFG call destination keys cache."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.knowledge_plugins.cfg.cfg_node import CFGNode
from angr.knowledge_plugins.cfg.spilling_cfg import SpillingCFG, get_block_key

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _make_node(addr, size=10):
    """Create a minimal CFGNode for testing."""
    return CFGNode(addr, size, None, block_id=addr)


def _make_graph():
    """Create a fresh SpillingCFG for testing."""
    return SpillingCFG(rtdb=None, cfg_model=None)


class TestCallDstCacheAddEdge(unittest.TestCase):
    """Test that add_edge correctly populates _call_dst_keys."""

    def test_call_edge_adds_dst(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        assert get_block_key(n2) in g.call_destination_keys

    def test_syscall_edge_adds_dst(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Syscall")
        assert get_block_key(n2) in g.call_destination_keys

    def test_sys_prefix_edge_adds_dst(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Sys_int128")
        assert get_block_key(n2) in g.call_destination_keys

    def test_boring_edge_does_not_add(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Boring")
        assert get_block_key(n2) not in g.call_destination_keys

    def test_no_jumpkind_does_not_add(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2)
        assert get_block_key(n2) not in g.call_destination_keys

    def test_multiple_call_edges_same_dst(self):
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n3, jumpkind="Ijk_Call")
        g.add_edge(n2, n3, jumpkind="Ijk_Call")
        assert get_block_key(n3) in g.call_destination_keys

    def test_mixed_jumpkinds(self):
        g = _make_graph()
        n1, n2, n3, n4 = (
            _make_node(0x1000),
            _make_node(0x2000),
            _make_node(0x3000),
            _make_node(0x4000),
        )
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.add_edge(n1, n3, jumpkind="Ijk_Boring")
        g.add_edge(n1, n4, jumpkind="Ijk_Syscall")
        assert g.call_destination_keys == {get_block_key(n2), get_block_key(n4)}


class TestCallDstCacheRemoveEdge(unittest.TestCase):
    """Test that remove_edge correctly maintains _call_dst_keys."""

    def test_remove_sole_call_edge(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.remove_edge(n1, n2)
        assert get_block_key(n2) not in g.call_destination_keys

    def test_remove_one_of_two_call_edges(self):
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n3, jumpkind="Ijk_Call")
        g.add_edge(n2, n3, jumpkind="Ijk_Call")
        g.remove_edge(n1, n3)
        # n3 should still be a call destination (n2->n3 remains)
        assert get_block_key(n3) in g.call_destination_keys

    def test_remove_both_call_edges(self):
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n3, jumpkind="Ijk_Call")
        g.add_edge(n2, n3, jumpkind="Ijk_Call")
        g.remove_edge(n1, n3)
        g.remove_edge(n2, n3)
        assert get_block_key(n3) not in g.call_destination_keys

    def test_remove_boring_edge_no_effect(self):
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.add_edge(n1, n3, jumpkind="Ijk_Boring")
        g.remove_edge(n1, n3)
        assert get_block_key(n2) in g.call_destination_keys


class TestCallDstCacheRemoveNode(unittest.TestCase):
    """Test that remove_node correctly maintains _call_dst_keys."""

    def test_remove_dst_node(self):
        """Removing a call destination node removes it from the cache."""
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.remove_node(n2)
        assert get_block_key(n2) not in g.call_destination_keys

    def test_remove_src_node_with_sole_call_edge(self):
        """Removing a source node that is the only caller removes dst from cache."""
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.remove_node(n1)
        assert get_block_key(n2) not in g.call_destination_keys

    def test_remove_src_node_with_other_callers(self):
        """Removing one caller when another exists keeps dst in cache."""
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n3, jumpkind="Ijk_Call")
        g.add_edge(n2, n3, jumpkind="Ijk_Call")
        g.remove_node(n1)
        assert get_block_key(n3) in g.call_destination_keys

    def test_remove_node_with_multiple_outgoing_calls(self):
        """Removing a node with multiple outgoing call edges updates all destinations."""
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.add_edge(n1, n3, jumpkind="Ijk_Call")
        g.remove_node(n1)
        assert get_block_key(n2) not in g.call_destination_keys
        assert get_block_key(n3) not in g.call_destination_keys

    def test_remove_isolated_node(self):
        """Removing a node with no edges doesn't crash."""
        g = _make_graph()
        n1 = _make_node(0x1000)
        g.add_node(n1)
        g.remove_node(n1)
        assert g.call_destination_keys == set()


class TestCallDstCacheNodes(unittest.TestCase):
    """Test call_destination_nodes method."""

    def test_returns_cfg_nodes(self):
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.add_edge(n1, n3, jumpkind="Ijk_Syscall")
        nodes = list(g.call_destination_nodes())
        assert len(nodes) == 2
        addrs = {n.addr for n in nodes}
        assert addrs == {0x2000, 0x3000}
        for n in nodes:
            assert isinstance(n, CFGNode)

    def test_empty_graph(self):
        g = _make_graph()
        assert not list(g.call_destination_nodes())


class TestCallDstCacheCopy(unittest.TestCase):
    """Test that copy() correctly copies _call_dst_keys."""

    def test_copy_preserves_cache(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g2 = g.copy()
        assert g2.call_destination_keys == g.call_destination_keys

    def test_copy_is_independent(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g2 = g.copy()
        g2.remove_edge(n1, n2)
        # Original should be unaffected
        assert get_block_key(n2) in g.call_destination_keys
        assert get_block_key(n2) not in g2.call_destination_keys


class TestCallDstCacheFromNetworkx(unittest.TestCase):
    """Test that from_networkx repopulates _call_dst_keys."""

    def test_from_networkx_repopulates(self):
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.add_edge(n1, n3, jumpkind="Ijk_Boring")

        nx_graph = g.to_networkx()
        g2 = _make_graph()
        g2.from_networkx(nx_graph)
        assert g2.call_destination_keys == {get_block_key(n2)}


class TestCallDstCachePickle(unittest.TestCase):
    """Test pickling reconstructs _call_dst_keys from edges."""

    def test_getstate_does_not_include_cache(self):
        g = _make_graph()
        n1, n2 = _make_node(0x1000), _make_node(0x2000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        state = g.__getstate__()
        assert "call_dst_keys" not in state

    def test_setstate_rebuilds_cache(self):
        g = _make_graph()
        n1, n2, n3 = _make_node(0x1000), _make_node(0x2000), _make_node(0x3000)
        g.add_edge(n1, n2, jumpkind="Ijk_Call")
        g.add_edge(n1, n3, jumpkind="Ijk_Syscall")
        state = g.__getstate__()
        g2 = SpillingCFG.__new__(SpillingCFG)
        g2.__setstate__(state)
        assert g2.call_destination_keys == {get_block_key(n2), get_block_key(n3)}


class TestCallDstCacheConsistency(unittest.TestCase):
    """Verify cache matches a full edge scan (debug assertion from the plan)."""

    def _compute_call_dsts_from_edges(self, g):
        """Compute call destination keys by scanning all edges."""
        result = set()
        for _, dst, data in g.edges(data=True):
            jk = data.get("jumpkind", "")
            if jk == "Ijk_Call" or jk.startswith("Ijk_Sys"):
                result.add(get_block_key(dst))
        return result

    def test_consistency_after_adds(self):
        g = _make_graph()
        nodes = [_make_node(0x1000 + i * 0x1000) for i in range(6)]
        g.add_edge(nodes[0], nodes[1], jumpkind="Ijk_Call")
        g.add_edge(nodes[0], nodes[2], jumpkind="Ijk_Boring")
        g.add_edge(nodes[2], nodes[3], jumpkind="Ijk_Syscall")
        g.add_edge(nodes[3], nodes[4], jumpkind="Ijk_Call")
        g.add_edge(nodes[4], nodes[5], jumpkind="Ijk_Ret")
        assert g.call_destination_keys == self._compute_call_dsts_from_edges(g)

    def test_consistency_after_removes(self):
        g = _make_graph()
        nodes = [_make_node(0x1000 + i * 0x1000) for i in range(5)]
        g.add_edge(nodes[0], nodes[1], jumpkind="Ijk_Call")
        g.add_edge(nodes[1], nodes[2], jumpkind="Ijk_Call")
        g.add_edge(nodes[2], nodes[3], jumpkind="Ijk_Syscall")
        g.add_edge(nodes[3], nodes[4], jumpkind="Ijk_Boring")
        g.remove_edge(nodes[0], nodes[1])
        g.remove_node(nodes[2])
        assert g.call_destination_keys == self._compute_call_dsts_from_edges(g)


class TestCallDstCacheIntegration(unittest.TestCase):
    """Integration test with a real binary."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_cache_matches_edge_scan(self):
        """Verify cache matches a brute-force edge scan on a real CFG."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        graph = cfg.model.graph

        # Compute expected from full edge scan
        expected = set()
        for _, dst, data in graph.edges(data=True):
            jk = data.get("jumpkind", "")
            if jk == "Ijk_Call" or jk.startswith("Ijk_Sys"):
                expected.add(get_block_key(dst))

        assert graph.call_destination_keys == expected


if __name__ == "__main__":
    unittest.main()
