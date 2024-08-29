#!/usr/bin/env python3
from __future__ import annotations
import networkx
import unittest

from angr.analyses.cfg_slice_to_sink import CFGSliceToSink, slice_callgraph, slice_cfg_graph, slice_function_graph


class _MockCFGNode:
    def __init__(self, addr):
        self.addr = addr

    def __repr__(self):
        return f"{self.addr}"


def _a_graph_and_its_nodes():
    # Build the following graph (addresses displayed):
    # 0 -> 1, 1 -> 2, 0 -> 3
    graph = networkx.DiGraph()
    nodes = list(map(_MockCFGNode, range(4)))
    graph.add_edge(nodes[0], nodes[1])
    graph.add_edge(nodes[1], nodes[2])
    graph.add_edge(nodes[0], nodes[3])
    return (graph, nodes)


class TestGraph(unittest.TestCase):
    def test_slice_callgraph_remove_content_not_in_a_cfg_slice_to_sink(self):
        my_callgraph, nodes = _a_graph_and_its_nodes()

        # Let's imagine a node (0x42), not a function entry point, not in my_callgraph, such as:
        # 1 -> 0x42, 0x42 -> 2
        transitions = {nodes[0]: [nodes[1]], nodes[1]: [0x42], 0x42: [nodes[2]]}
        cfg_slice_to_sink = CFGSliceToSink(None, transitions)

        sliced_callgraph = slice_callgraph(my_callgraph, cfg_slice_to_sink)

        result_nodes = list(sliced_callgraph.nodes)
        result_edges = list(sliced_callgraph.edges)

        self.assertListEqual(result_nodes, [nodes[0], nodes[1], nodes[2]])
        self.assertListEqual(result_edges, [(nodes[0], nodes[1]), (nodes[1], nodes[2])])

    def test_slice_callgraph_mutates_the_original_graph(self):
        my_callgraph, nodes = _a_graph_and_its_nodes()

        # Let's imagine a node (0x42), not a function entry point, not in my_callgraph, such as:
        # 1 -> 0x42, 0x42 -> 2
        transitions = {nodes[0]: [nodes[1]], nodes[1]: [0x42], 0x42: [nodes[2]]}
        cfg_slice_to_sink = CFGSliceToSink(None, transitions)

        sliced_callgraph = slice_callgraph(my_callgraph, cfg_slice_to_sink)

        self.assertEqual(len(my_callgraph.nodes), 3)
        self.assertEqual(len(my_callgraph.edges), 2)
        self.assertEqual(my_callgraph, sliced_callgraph)

    def test_slice_cfg_graph_remove_content_not_in_a_cfg_slice_to_sink(self):
        my_graph, nodes = _a_graph_and_its_nodes()

        transitions = {nodes[0].addr: [nodes[1].addr], nodes[1].addr: [nodes[2].addr]}
        my_slice = CFGSliceToSink(None, transitions)

        sliced_graph = slice_cfg_graph(my_graph, my_slice)
        result_nodes = list(sliced_graph.nodes)
        result_edges = list(sliced_graph.edges)

        self.assertListEqual(result_nodes, [nodes[0], nodes[1], nodes[2]])
        self.assertListEqual(result_edges, [(nodes[0], nodes[1]), (nodes[1], nodes[2])])

    def test_slice_cfg_graph_mutates_the_original_graph(self):
        my_graph, nodes = _a_graph_and_its_nodes()

        transitions = {nodes[0].addr: [nodes[1].addr]}
        my_slice = CFGSliceToSink(None, transitions)

        sliced_graph = slice_cfg_graph(my_graph, my_slice)

        self.assertEqual(len(my_graph.nodes), 2)
        self.assertEqual(len(my_graph.edges), 1)
        self.assertEqual(my_graph, sliced_graph)

    def test_slice_function_graph_remove_nodes_not_in_a_cfg_slice_to_sink(self):
        # Imagine a CFG being:    0 -> 0x42, 0x42 -> 1, 1 -> 2, 0 -> 3
        # And the function graph: 0 -> 1, 1 -> 2, 0 -> 3
        my_function_graph, nodes = _a_graph_and_its_nodes()

        transitions = {nodes[0].addr: [0x42], 0x42: [nodes[1].addr]}
        my_slice = CFGSliceToSink(None, transitions)

        sliced_function_graph = slice_function_graph(my_function_graph, my_slice)
        result_nodes = list(sliced_function_graph.nodes)
        result_edges = list(sliced_function_graph.edges)

        self.assertListEqual(result_nodes, [nodes[0], nodes[1]])
        self.assertListEqual(result_edges, [(nodes[0], nodes[1])])

    def test_slice_function_graph_mutates_the_original_function_graph(self):
        # Imagine a CFG being:    0 -> 0x42, 0x42 -> 1, 1 -> 2, 0 -> 3
        # And the function graph: 0 -> 1, 1 -> 2, 0 -> 3
        my_function_graph, nodes = _a_graph_and_its_nodes()

        transitions = {nodes[0].addr: [0x42], 0x42: [nodes[1].addr]}
        my_slice = CFGSliceToSink(None, transitions)

        sliced_function_graph = slice_function_graph(my_function_graph, my_slice)

        self.assertEqual(len(my_function_graph.nodes), 2)
        self.assertEqual(len(my_function_graph.edges), 1)
        self.assertEqual(my_function_graph, sliced_function_graph)


if __name__ == "__main__":
    unittest.main()
