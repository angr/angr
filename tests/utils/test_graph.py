#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

import unittest
import unittest.mock

import networkx as nx

from angr.ailment.block import Block
from angr.utils.graph import Dominators, GraphUtils, TemporaryNode, subgraph_between_nodes


class TestGraph(unittest.TestCase):
    def test_dominators(self):
        G = nx.DiGraph()
        G.add_edge("1", "2")
        G.add_edge("1", "3")
        G.add_edge("2", "5")
        G.add_edge("2", "7")
        G.add_edge("3", "4")
        G.add_edge("4", "5")
        G.add_edge("4", "6")
        G.add_edge("4", "7")
        G.add_edge("5", "8")
        G.add_edge("7", "8")
        G.add_edge("8", "6")
        d = Dominators(G, "1")
        start_node = TemporaryNode("start_node")
        end_node = TemporaryNode("end_node")
        idom_succ = {
            start_node: {"1": {}},
            "1": {"2": {}, "3": {}, "5": {}, "6": {}, "7": {}, "8": {}},
            "2": {},
            "3": {"4": {}},
            "4": {},
            "5": {},
            "6": {end_node: {}},
            "7": {},
            "8": {},
            end_node: {},
        }
        assert d.dom.succ == idom_succ

    def test_quasi_topological_sort_nodes_panic_mode_int_nodes(self):
        G = nx.DiGraph()
        num_nodes = 100
        for src in range(num_nodes):
            for dst in range(num_nodes):
                G.add_edge(src, dst)
        G_sorted = GraphUtils.quasi_topological_sort_nodes(G, panic_mode_threshold=num_nodes // 2)
        assert G_sorted == list(range(num_nodes))

    def test_quasi_topological_sort_nodes_panic_mode_ail_block_nodes(self):
        G = nx.DiGraph()
        num_nodes = 100
        nodes = [Block(i, 20) for i in range(num_nodes)]
        for src in range(num_nodes):
            for dst in range(num_nodes):
                G.add_edge(nodes[src], nodes[dst])
        G_sorted = GraphUtils.quasi_topological_sort_nodes(G, panic_mode_threshold=num_nodes // 2)
        assert G_sorted == nodes

    def test_subgraph_between_nodes_basic(self):
        G = nx.DiGraph()
        G.add_edge("head", "a", weight=1)
        G.add_edge("a", "b")
        G.add_edge("b", "latch")
        G.add_edge("head", "dead_end")
        G.add_edge("latch", "head")

        g0 = subgraph_between_nodes(G, "head", ["latch"])
        assert set(g0.nodes) == {"head", "a", "b"}
        assert set(g0.edges) == {("head", "a"), ("a", "b")}
        assert g0.edges["head", "a"]["weight"] == 1

        g1 = subgraph_between_nodes(G, "head", ["latch"], include_frontier=True)
        assert set(g1.nodes) == {"head", "a", "b", "latch"}
        assert set(g1.edges) == {("head", "a"), ("a", "b"), ("b", "latch")}

    def test_subgraph_between_nodes_does_not_explore_unreachable_region(self):
        # A loop head with a direct latch edge and a second edge into a large side region that only loops back to
        # the head. Since all incoming edges of the source are ignored, the side region cannot reach the latch, and
        # proving that must not cost a traversal of the side region per (candidate, frontier) pair.
        side_nodes = 20000
        G = nx.DiGraph()
        head, latch = side_nodes, side_nodes + 1
        G.add_edge(head, latch)
        G.add_edge(head, 0)
        G.add_edges_from((n, n + 1) for n in range(side_nodes - 1))
        G.add_edge(side_nodes - 1, 0)
        G.add_edge(side_nodes - 1, head)

        has_path_calls = 0
        real_has_path = nx.has_path

        def counting_has_path(*args, **kwargs):
            nonlocal has_path_calls
            has_path_calls += 1
            return real_has_path(*args, **kwargs)

        with unittest.mock.patch.object(nx, "has_path", counting_has_path):
            g0 = subgraph_between_nodes(G, head, [latch], include_frontier=True)

        assert list(g0.nodes) == [head, latch]
        assert list(g0.edges) == [(head, latch)]
        assert has_path_calls == 0


if __name__ == "__main__":
    unittest.main()
