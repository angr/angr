#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations
import unittest
import networkx as nx
from ailment.block import Block
from angr.utils.graph import Dominators, TemporaryNode, GraphUtils


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


if __name__ == "__main__":
    unittest.main()
