#!/usr/bin/env python3
# pylint:disable=missing-class-docstring
"""Test cases for SpillingCFGGraph and SpillingCFGNodeDict functionality."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSpillingCFGNodeDict(unittest.TestCase):
    """Test cases for SpillingCFGNodeDict standalone functionality."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_basic_operations(self):
        """Test basic dict operations on SpillingCFGNodeDict."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        # Access the nodes dict through the graph
        nodes = cfg.model.graph._nodes

        # Test __len__
        assert len(nodes) > 0, "Should have nodes"

        # Test __contains__
        for block_id in list(nodes.keys())[:3]:
            assert block_id in nodes, f"Block ID {block_id} should be in nodes"

        # Test __iter__
        count = 0
        for _ in nodes:
            count += 1
        assert count == len(nodes), "Iteration count should match length"

    def test_lru_eviction(self):
        """Test LRU eviction behavior with small cache limit."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        graph = cfg.model.graph
        total_nodes = len(graph)

        if total_nodes <= 5:
            self.skipTest("Binary has too few nodes to test eviction")

        # Set small cache limit to trigger eviction
        graph.cache_limit = 5
        graph.db_batch_size = 1

        # Check that spilling occurred
        assert graph.spilled_count > 0, "Should have spilled some nodes"
        assert graph.cached_count <= 6, "Cache limit should be respected"
        # All nodes should still be accessible
        assert len(graph) == total_nodes, "Graph node count should be preserved"


class TestSpillingCFGGraph(unittest.TestCase):
    """Test cases for SpillingCFGGraph functionality."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_default_no_spilling(self):
        """Test that default behavior has no spilling (cache_limit=None)."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        graph = cfg.model.graph

        assert graph.cache_limit is None, "Default should have no cache limit"
        assert graph.spilled_count == 0, "Should have no spilled nodes"

    def test_nodes_iteration(self):
        """Test iterating over nodes returns CFGNode instances."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        from angr.knowledge_plugins.cfg.cfg_node import CFGNode

        for node in cfg.model.graph.nodes():
            assert isinstance(node, CFGNode), f"Expected CFGNode, got {type(node)}"
            break  # Just check the first one

    def test_edges_iteration(self):
        """Test iterating over edges returns CFGNode tuples."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        from angr.knowledge_plugins.cfg.cfg_node import CFGNode

        for src, dst in cfg.model.graph.edges():
            assert isinstance(src, CFGNode), f"Expected CFGNode src, got {type(src)}"
            assert isinstance(dst, CFGNode), f"Expected CFGNode dst, got {type(dst)}"
            break

    def test_edges_with_data(self):
        """Test iterating over edges with data."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for _, _, data in cfg.model.graph.edges(data=True):
            assert isinstance(data, dict), f"Expected dict, got {type(data)}"
            assert "jumpkind" in data, "Edge should have jumpkind"
            break

    def test_successors_predecessors(self):
        """Test successors and predecessors methods."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        from angr.knowledge_plugins.cfg.cfg_node import CFGNode

        # Find a node with successors
        for node in cfg.model.graph.nodes():
            succs = list(cfg.model.graph.successors(node))
            if succs:
                for succ in succs:
                    assert isinstance(succ, CFGNode), "Successor should be CFGNode"
                # Check that node is in predecessor list of its successor
                preds = list(cfg.model.graph.predecessors(succs[0]))
                assert node in preds, "Node should be in predecessor list of its successor"
                break

    def test_contains(self):
        """Test __contains__ for node membership."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for node in cfg.model.graph.nodes():
            assert node in cfg.model.graph, "Node should be in graph"
            break

    def test_has_edge(self):
        """Test has_edge method."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for src, dst in cfg.model.graph.edges():
            assert cfg.model.graph.has_edge(src, dst), "Edge should exist"
            break

    def test_adjacency_access(self):
        """Test graph[src][dst] access pattern."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for src, dst, expected_data in cfg.model.graph.edges(data=True):
            actual_data = cfg.model.graph[src][dst]
            assert actual_data == expected_data, "Adjacency access should return edge data"
            break

    def test_in_edges_out_edges(self):
        """Test in_edges and out_edges methods."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for node in cfg.model.graph.nodes():
            # Test out_edges
            out_list = list(cfg.model.graph.out_edges([node], data=True))
            for src, _, data in out_list:
                assert src == node, "Source should be the queried node"
                assert isinstance(data, dict), "Data should be dict"

            # Test in_edges
            in_list = list(cfg.model.graph.in_edges([node], data=True))
            for _, dst, _ in in_list:
                assert dst == node, "Destination should be the queried node"

            if out_list or in_list:
                break


class TestSpillingCFGGraphWithSpilling(unittest.TestCase):
    """Test cases for SpillingCFGGraph with spilling enabled."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_spilling_enabled(self):
        """Test CFG construction with spilling enabled."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        graph = cfg.model.graph
        total = len(graph)

        if total <= 5:
            self.skipTest("Binary too small to test spilling")

        graph.db_batch_size = 1
        graph.cache_limit = 5

        assert graph.cache_limit == 5, "Cache limit should be set"
        assert graph.spilled_count > 0, "Should have spilled nodes"
        # Graph should still have all nodes accessible
        assert len(graph) == total, "Graph node count preserved"

    def test_access_spilled_node(self):
        """Test accessing a spilled node loads it correctly."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        graph = cfg.model.graph

        if len(graph) <= 3:
            self.skipTest("Binary too small to test spilling")

        # Enable spilling
        graph.db_batch_size = 1
        graph.cache_limit = 3

        if graph.spilled_count == 0:
            self.skipTest("No spilled nodes to test")

        # Iterate and access all nodes - spilled ones should be loaded
        from angr.knowledge_plugins.cfg.cfg_node import CFGNode

        for node in graph.nodes():
            assert isinstance(node, CFGNode), "Should get CFGNode instances"
            assert node.addr is not None, "Node should have valid address"

    def test_graph_traversal_with_spilling(self):
        """Test graph traversal works correctly with spilled nodes."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        # Enable spilling
        cfg.model.graph.cache_limit = 3

        # Use CFGModel methods that traverse the graph
        model = cfg.model

        # Try to get successors/predecessors
        for node in model.graph.nodes():
            succs = model.get_successors(node)
            preds = model.get_predecessors(node)
            # Just verify these don't crash
            assert isinstance(succs, list)
            assert isinstance(preds, list)
            break

    def test_copy_with_spilling(self):
        """Test copying a CFGModel with spilled nodes."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        # Enable spilling
        cfg.model.graph.cache_limit = 5

        original = cfg.model
        copied = original.copy()

        # Verify counts match
        assert len(copied.graph) == len(original.graph), "Node count should match"

        # Verify nodes are accessible in copy
        for node in copied.graph.nodes():
            assert node is not None
            break


class TestCFGModelIntegration(unittest.TestCase):
    """Integration tests for CFGModel with SpillingCFGGraph."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_nodes_property(self):
        """Test that CFGModel._nodes property works correctly."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        model = cfg.model

        # _nodes should delegate to graph._nodes
        assert model._nodes is model.graph._nodes, "_nodes should be graph._nodes"

    def test_get_node(self):
        """Test CFGModel.get_node method."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        model = cfg.model

        # Get block IDs from the block ID to block key mapping
        # note that block IDs and block keys are different. Block IDs are generated by the CFG analysis, while block
        # keys are internal to the CFGModel.
        for block_id in model._blockid_to_blockkey:
            node = model.get_node(block_id)
            assert node is not None, "Should get node by block_id"
            assert node.block_id == block_id, "Block ID should match"
            break

    def test_get_any_node(self):
        """Test CFGModel.get_any_node method."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        model = cfg.model

        # Get a node address
        for node in model.graph.nodes():
            found = model.get_any_node(node.addr)
            assert found is not None, "Should find node by address"
            assert found.addr == node.addr, "Address should match"
            break

    def test_cfg_model_nodes_method(self):
        """Test CFGModel.nodes() method."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        nodes_list = list(cfg.model.nodes())
        assert len(nodes_list) > 0, "Should have nodes"
        assert len(nodes_list) == len(cfg.model.graph), "Count should match"


if __name__ == "__main__":
    unittest.main()
