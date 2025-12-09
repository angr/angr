#!/usr/bin/env python3
"""
Tests for RxDiGraph, a networkx.DiGraph-compatible wrapper around rustworkx.PyDiGraph.
Verifying it behaves equivalently to networkx.DiGraph.
"""
from __future__ import annotations

import unittest
import networkx
from angr.knowledge_plugins.cfg.cfg_graph import RxDiGraph


class FakeCFGNode:
    """Fake CFGNode-like object for testing"""

    __slots__ = ("addr", "size")

    def __init__(self, addr, size=4):
        self.addr = addr
        self.size = size

    def __repr__(self):
        return f"Node({self.addr:#x})"

    def __eq__(self, other):
        return isinstance(other, FakeCFGNode) and self.addr == other.addr

    def __hash__(self):
        return hash(self.addr)


class TestRxDiGraph(unittest.TestCase):
    """
    Tests that verify RxDiGraph works identically to networkx.DiGraph
    """

    def setUp(self):
        self.n1 = FakeCFGNode(0x100)
        self.n2 = FakeCFGNode(0x200)
        self.n3 = FakeCFGNode(0x300)
        self.n4 = FakeCFGNode(0x400)
        self.n5 = FakeCFGNode(0x500)

    def _edges_to_hashable(self, edges):
        # convert edge tuples with dict data to hashable form for set comparison
        result = []
        for edge in edges:
            if len(edge) == 3:
                # (src, dst, data_dict) -> (src, dst, frozenset(data_dict.items()))
                src, dst, data = edge
                result.append((src, dst, frozenset(data.items())))
            else:
                # (src, dst) -> just return as is
                result.append(edge)
        return set(result)

    def test_add_node_and_contains(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_node(self.n1)
        nx_g.add_node(self.n1)

        self.assertEqual(self.n1 in rx_g, self.n1 in nx_g)
        self.assertEqual(self.n2 in rx_g, self.n2 in nx_g)
        self.assertTrue(self.n1 in rx_g)
        self.assertFalse(self.n2 in rx_g)

    def test_add_edge(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, weight=10)
        nx_g.add_edge(self.n1, self.n2, weight=10)

        self.assertTrue(self.n1 in rx_g)
        self.assertTrue(self.n2 in rx_g)

    def test_nodes_iteration(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        self.assertEqual(set(rx_g.nodes), set(nx_g.nodes))
        self.assertEqual(len(rx_g.nodes), 3)

    def test_edges_len(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n2, self.n3)

        self.assertEqual(len(rx_g.edges), len(nx_g.edges))

    def test_successors(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n1, self.n3)

        self.assertEqual(set(rx_g.successors(self.n1)), set(nx_g.successors(self.n1)))

    def test_predecessors(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n3)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n2, self.n3)

        self.assertEqual(set(rx_g.predecessors(self.n3)), set(nx_g.predecessors(self.n3)))

    def test_remove_node(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n2, self.n3)

        rx_g.remove_node(self.n2)
        nx_g.remove_node(self.n2)

        self.assertEqual(self.n2 in rx_g, self.n2 in nx_g)
        self.assertFalse(self.n2 in rx_g)

    def test_out_edges(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n1, self.n3)

        rx_out = rx_g.out_edges(self.n1)
        nx_out = list(nx_g.out_edges(self.n1))

        self.assertEqual(len(rx_out), len(nx_out))

    def test_add_edge_with_type_and_metadata(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, type="transition", outside=False, ins_addr=0x100, stmt_idx=0)
        nx_g.add_edge(self.n1, self.n2, type="transition", outside=False, ins_addr=0x100, stmt_idx=0)

        rx_g.add_edge(self.n2, self.n3, type="call", stmt_idx=1, ins_addr=0x200)
        nx_g.add_edge(self.n2, self.n3, type="call", stmt_idx=1, ins_addr=0x200)

        rx_g.add_edge(self.n3, self.n4, type="fake_return", confirmed=True, outside=False)
        nx_g.add_edge(self.n3, self.n4, type="fake_return", confirmed=True, outside=False)

        self.assertEqual(rx_g.get_edge_data(self.n1, self.n2), nx_g.get_edge_data(self.n1, self.n2))
        self.assertEqual(rx_g.get_edge_data(self.n2, self.n3), nx_g.get_edge_data(self.n2, self.n3))
        self.assertEqual(rx_g.get_edge_data(self.n3, self.n4), nx_g.get_edge_data(self.n3, self.n4))

    def test_add_edge_with_jumpkind(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, jumpkind="Ijk_Boring", ins_addr=0x100, stmt_idx=0)
        nx_g.add_edge(self.n1, self.n2, jumpkind="Ijk_Boring", ins_addr=0x100, stmt_idx=0)

        rx_g.add_edge(self.n2, self.n3, jumpkind="Ijk_Call")
        nx_g.add_edge(self.n2, self.n3, jumpkind="Ijk_Call")

        rx_g.add_edge(self.n2, self.n4, jumpkind="Ijk_FakeRet")
        nx_g.add_edge(self.n2, self.n4, jumpkind="Ijk_FakeRet")

        self.assertEqual(rx_g.get_edge_data(self.n1, self.n2), nx_g.get_edge_data(self.n1, self.n2))
        self.assertEqual(rx_g.get_edge_data(self.n2, self.n3), nx_g.get_edge_data(self.n2, self.n3))
        self.assertEqual(rx_g.get_edge_data(self.n2, self.n4), nx_g.get_edge_data(self.n2, self.n4))

    def test_in_edges_with_data(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n3, jumpkind="Ijk_Boring")
        rx_g.add_edge(self.n2, self.n3, jumpkind="Ijk_Call")
        nx_g.add_edge(self.n1, self.n3, jumpkind="Ijk_Boring")
        nx_g.add_edge(self.n2, self.n3, jumpkind="Ijk_Call")

        rx_in = list(rx_g.in_edges(self.n3, data=True))
        nx_in = list(nx_g.in_edges(self.n3, data=True))

        self.assertEqual(len(rx_in), len(nx_in))
        self.assertEqual(self._edges_to_hashable(rx_in), self._edges_to_hashable(nx_in))

        for pred, _, data in rx_g.in_edges(self.n3, data=True):
            jk = data["jumpkind"]
            self.assertIn(jk, ["Ijk_Boring", "Ijk_Call"])

    def test_in_edges_with_nbunch_list(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n3, jumpkind="Ijk_Boring")
        rx_g.add_edge(self.n2, self.n3, jumpkind="Ijk_Call")
        nx_g.add_edge(self.n1, self.n3, jumpkind="Ijk_Boring")
        nx_g.add_edge(self.n2, self.n3, jumpkind="Ijk_Call")

        rx_in = list(rx_g.in_edges([self.n3], data=True))
        nx_in = list(nx_g.in_edges([self.n3], data=True))

        self.assertEqual(self._edges_to_hashable(rx_in), self._edges_to_hashable(nx_in))

    def test_out_edges_with_data(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, jumpkind="Ijk_Boring")
        rx_g.add_edge(self.n1, self.n3, jumpkind="Ijk_Call")
        rx_g.add_edge(self.n1, self.n4, jumpkind="Ijk_FakeRet")
        nx_g.add_edge(self.n1, self.n2, jumpkind="Ijk_Boring")
        nx_g.add_edge(self.n1, self.n3, jumpkind="Ijk_Call")
        nx_g.add_edge(self.n1, self.n4, jumpkind="Ijk_FakeRet")

        rx_out = list(rx_g.out_edges(self.n1, data=True))
        nx_out = list(nx_g.out_edges(self.n1, data=True))

        self.assertEqual(len(rx_out), len(nx_out))
        self.assertEqual(self._edges_to_hashable(rx_out), self._edges_to_hashable(nx_out))

    def test_out_edges_filter_by_jumpkind(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, jumpkind="Ijk_Boring")
        rx_g.add_edge(self.n1, self.n3, jumpkind="Ijk_FakeRet")
        nx_g.add_edge(self.n1, self.n2, jumpkind="Ijk_Boring")
        nx_g.add_edge(self.n1, self.n3, jumpkind="Ijk_FakeRet")

        rx_filtered = [e for e in rx_g.out_edges(self.n1, data=True) if e[2]["jumpkind"] != "Ijk_FakeRet"]
        nx_filtered = [e for e in nx_g.out_edges(self.n1, data=True) if e[2]["jumpkind"] != "Ijk_FakeRet"]

        self.assertEqual(len(rx_filtered), len(nx_filtered))
        self.assertEqual(rx_filtered[0][2]["jumpkind"], "Ijk_Boring")

    def test_in_degree_subscript(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n3)
        rx_g.add_edge(self.n2, self.n3)
        rx_g.add_edge(self.n4, self.n3)
        nx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n4, self.n3)

        self.assertEqual(rx_g.in_degree[self.n3], nx_g.in_degree[self.n3])
        self.assertEqual(rx_g.in_degree[self.n1], nx_g.in_degree[self.n1])
        self.assertEqual(rx_g.in_degree[self.n3], 3)
        self.assertEqual(rx_g.in_degree[self.n1], 0)

    def test_out_degree_subscript(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n1, self.n3)
        rx_g.add_edge(self.n1, self.n4)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n1, self.n4)

        self.assertEqual(rx_g.out_degree[self.n1], nx_g.out_degree[self.n1])
        self.assertEqual(rx_g.out_degree[self.n2], nx_g.out_degree[self.n2])
        self.assertEqual(rx_g.out_degree[self.n1], 3)
        self.assertEqual(rx_g.out_degree[self.n2], 0)

    def test_degree_in_list_comprehension(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3, self.n4]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n1, self.n3)

        rx_roots = [n for n in rx_g.nodes if rx_g.in_degree[n] == 0]
        nx_roots = [n for n in nx_g.nodes if nx_g.in_degree[n] == 0]

        self.assertEqual(set(rx_roots), set(nx_roots))

    def test_successors(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n1, self.n3)
        rx_g.add_edge(self.n1, self.n4)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n1, self.n4)

        rx_succ = list(rx_g.successors(self.n1))
        nx_succ = list(nx_g.successors(self.n1))

        self.assertEqual(set(rx_succ), set(nx_succ))

    def test_predecessors(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n4)
        rx_g.add_edge(self.n2, self.n4)
        rx_g.add_edge(self.n3, self.n4)
        nx_g.add_edge(self.n1, self.n4)
        nx_g.add_edge(self.n2, self.n4)
        nx_g.add_edge(self.n3, self.n4)

        rx_pred = list(rx_g.predecessors(self.n4))
        nx_pred = list(nx_g.predecessors(self.n4))

        self.assertEqual(set(rx_pred), set(nx_pred))

    def test_predecessors_in_iteration(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n3)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n2, self.n3)

        rx_preds = list(rx_g.predecessors(self.n3))
        nx_preds = list(nx_g.predecessors(self.n3))

        self.assertEqual(set(rx_preds), set(nx_preds))
        self.assertEqual(len(rx_preds), 2)

    def test_node_membership(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_node(self.n1)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_node(self.n1)
        nx_g.add_edge(self.n2, self.n3)

        self.assertEqual(self.n1 in rx_g, self.n1 in nx_g)
        self.assertEqual(self.n2 in rx_g, self.n2 in nx_g)
        self.assertEqual(self.n3 in rx_g, self.n3 in nx_g)
        self.assertEqual(self.n4 in rx_g, self.n4 in nx_g)

    def test_adjacency_access(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, weight=10)
        rx_g.add_edge(self.n1, self.n3, weight=20)
        nx_g.add_edge(self.n1, self.n2, weight=10)
        nx_g.add_edge(self.n1, self.n3, weight=20)

        rx_adj = rx_g[self.n1]
        nx_adj = nx_g[self.n1]

        self.assertEqual(set(rx_adj.keys()), set(nx_adj.keys()))
        self.assertIn(self.n2, rx_adj)
        self.assertIn(self.n3, rx_adj)

    def test_adjacency_edge_data(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, jumpkind="Ijk_Boring", ins_addr=0x100)
        nx_g.add_edge(self.n1, self.n2, jumpkind="Ijk_Boring", ins_addr=0x100)

        rx_data = rx_g[self.n1][self.n2]
        nx_data = nx_g[self.n1][self.n2]

        self.assertEqual(rx_data["jumpkind"], nx_data["jumpkind"])
        self.assertEqual(rx_data["ins_addr"], nx_data["ins_addr"])

    def test_mutate_edge_data_via_in_edges(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n3, type="fake_return", confirmed=False)
        rx_g.add_edge(self.n2, self.n3, type="call")
        nx_g.add_edge(self.n1, self.n3, type="fake_return", confirmed=False)
        nx_g.add_edge(self.n2, self.n3, type="call")

        # Pattern from function.py: _return_from_call
        # for _, _, data in self.transition_graph.in_edges(to_node, data=True):
        #     if "type" in data and data["type"] == "fake_return":
        #         data["confirmed"] = True
        for _, _, data in rx_g.in_edges(self.n3, data=True):
            if "type" in data and data["type"] == "fake_return":
                data["confirmed"] = True

        for _, _, data in nx_g.in_edges(self.n3, data=True):
            if "type" in data and data["type"] == "fake_return":
                data["confirmed"] = True

        # Verify mutation persisted
        rx_data = rx_g.get_edge_data(self.n1, self.n3)
        nx_data = nx_g.get_edge_data(self.n1, self.n3)

        self.assertEqual(rx_data["confirmed"], True)
        self.assertEqual(nx_data["confirmed"], True)
        self.assertEqual(rx_data, nx_data)

    def test_nodes_len(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        self.assertEqual(len(rx_g.nodes), len(nx_g.nodes))
        self.assertEqual(len(rx_g.nodes), 3)

    def test_nodes_iteration(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        self.assertEqual(set(rx_g.nodes), set(nx_g.nodes))

    def test_edges_len(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n2, self.n3)
        rx_g.add_edge(self.n3, self.n4)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n3, self.n4)

        self.assertEqual(len(rx_g.edges), len(nx_g.edges))

    def test_edges_iteration(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, weight=1)
        rx_g.add_edge(self.n2, self.n3, weight=2)
        nx_g.add_edge(self.n1, self.n2, weight=1)
        nx_g.add_edge(self.n2, self.n3, weight=2)

        # without data
        self.assertEqual(set(rx_g.edges), set(nx_g.edges))

        # with data
        rx_edges_data = list(rx_g.edges(data=True))
        nx_edges_data = list(nx_g.edges(data=True))
        self.assertEqual(self._edges_to_hashable(rx_edges_data), self._edges_to_hashable(nx_edges_data))

    def test_remove_node(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n2, self.n3)
        rx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n3)

        rx_g.remove_node(self.n2)
        nx_g.remove_node(self.n2)

        self.assertEqual(set(rx_g.nodes), set(nx_g.nodes))
        self.assertEqual(self.n2 in rx_g, self.n2 in nx_g)
        self.assertEqual(rx_g.has_edge(self.n1, self.n2), nx_g.has_edge(self.n1, self.n2))

    def test_remove_edge(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n2, self.n3)

        rx_g.remove_edge(self.n1, self.n2)
        nx_g.remove_edge(self.n1, self.n2)

        self.assertEqual(rx_g.has_edge(self.n1, self.n2), nx_g.has_edge(self.n1, self.n2))
        self.assertEqual(rx_g.has_edge(self.n2, self.n3), nx_g.has_edge(self.n2, self.n3))

        # nodes should still exist
        self.assertIn(self.n1, rx_g)
        self.assertIn(self.n2, rx_g)

    def test_copy(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, weight=10)
        rx_g.add_edge(self.n2, self.n3, weight=20)
        nx_g.add_edge(self.n1, self.n2, weight=10)
        nx_g.add_edge(self.n2, self.n3, weight=20)

        rx_copy = rx_g.copy()
        nx_copy = nx_g.copy()

        self.assertEqual(set(rx_copy.nodes), set(nx_copy.nodes))
        self.assertEqual(set(rx_copy.edges), set(nx_copy.edges))

        rx_g.add_node(self.n5)
        nx_g.add_node(self.n5)

        self.assertNotIn(self.n5, rx_copy)
        self.assertNotIn(self.n5, nx_copy)

    def test_has_edge(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n1, self.n2)

        self.assertEqual(rx_g.has_edge(self.n1, self.n2), nx_g.has_edge(self.n1, self.n2))
        self.assertEqual(rx_g.has_edge(self.n2, self.n1), nx_g.has_edge(self.n2, self.n1))
        self.assertEqual(rx_g.has_edge(self.n1, self.n3), nx_g.has_edge(self.n1, self.n3))

    def test_number_of_nodes(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        self.assertEqual(rx_g.number_of_nodes(), nx_g.number_of_nodes())

    def test_number_of_edges(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n2, self.n3)

        self.assertEqual(rx_g.number_of_edges(), nx_g.number_of_edges())

    def test_len_graph(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3, self.n4]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        self.assertEqual(len(rx_g), len(nx_g))
        self.assertEqual(len(rx_g), 4)

    def test_cfg_like_graph_operations(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        # make a small CFG-like structure
        # entry -> block1 -> block2 -> exit
        #                 -> block3 -> exit
        entry = FakeCFGNode(0x1000)
        block1 = FakeCFGNode(0x1010)
        block2 = FakeCFGNode(0x1020)
        block3 = FakeCFGNode(0x1030)
        exit_node = FakeCFGNode(0x1040)

        edges = [
            (entry, block1, {"jumpkind": "Ijk_Boring"}),
            (block1, block2, {"jumpkind": "Ijk_Boring"}),
            (block1, block3, {"jumpkind": "Ijk_Boring"}),
            (block2, exit_node, {"jumpkind": "Ijk_Ret"}),
            (block3, exit_node, {"jumpkind": "Ijk_Ret"}),
        ]

        for src, dst, data in edges:
            rx_g.add_edge(src, dst, **data)
            nx_g.add_edge(src, dst, **data)

        # test CFG operations
        self.assertEqual(rx_g.out_degree[block1], nx_g.out_degree[block1])
        self.assertEqual(rx_g.in_degree[exit_node], nx_g.in_degree[exit_node])
        self.assertEqual(set(rx_g.successors(block1)), set(nx_g.successors(block1)))
        self.assertEqual(set(rx_g.predecessors(exit_node)), set(nx_g.predecessors(exit_node)))

        # find nodes with in_degree == 0 (entry points)
        rx_entries = [n for n in rx_g.nodes if rx_g.in_degree[n] == 0]
        nx_entries = [n for n in nx_g.nodes if nx_g.in_degree[n] == 0]
        self.assertEqual(set(rx_entries), set(nx_entries))

        # find nodes with out_degree == 0 (exit points)
        rx_exits = [n for n in rx_g.nodes if rx_g.out_degree[n] == 0]
        nx_exits = [n for n in nx_g.nodes if nx_g.out_degree[n] == 0]
        self.assertEqual(set(rx_exits), set(nx_exits))

    def test_has_node(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_node(self.n1)
        nx_g.add_node(self.n1)

        self.assertEqual(rx_g.has_node(self.n1), nx_g.has_node(self.n1))
        self.assertEqual(rx_g.has_node(self.n2), nx_g.has_node(self.n2))
        self.assertTrue(rx_g.has_node(self.n1))
        self.assertFalse(rx_g.has_node(self.n2))

    def test_nodes_callable_with_data(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        rx_nodes_data = list(rx_g.nodes(data=True))
        nx_nodes_data = list(nx_g.nodes(data=True))

        # both should return list of (node, data_dict) tuples
        self.assertEqual(len(rx_nodes_data), len(nx_nodes_data))
        rx_node_set = {n for n, d in rx_nodes_data}
        nx_node_set = {n for n, d in nx_nodes_data}
        self.assertEqual(rx_node_set, nx_node_set)

    def test_edges_callable_without_data(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, weight=1)
        rx_g.add_edge(self.n2, self.n3, weight=2)
        nx_g.add_edge(self.n1, self.n2, weight=1)
        nx_g.add_edge(self.n2, self.n3, weight=2)

        # calling edges() should return iterable of edges
        rx_edges = list(rx_g.edges(data=False))
        nx_edges = list(nx_g.edges(data=False))

        self.assertEqual(set(rx_edges), set(nx_edges))

    def test_in_degree_iteration(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n3)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n2, self.n3)

        rx_degrees = dict(rx_g.in_degree)
        nx_degrees = dict(nx_g.in_degree)

        self.assertEqual(rx_degrees, nx_degrees)

    def test_out_degree_iteration(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n1, self.n3)

        rx_degrees = dict(rx_g.out_degree)
        nx_degrees = dict(nx_g.out_degree)

        self.assertEqual(rx_degrees, nx_degrees)

    def test_in_degree_callable_nbunch(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n3)
        rx_g.add_edge(self.n2, self.n3)
        rx_g.add_edge(self.n1, self.n4)
        nx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n4)

        # single node call returns int
        rx_single = rx_g.in_degree(self.n3)
        nx_single = nx_g.in_degree(self.n3)
        self.assertEqual(rx_single, nx_single)
        self.assertEqual(rx_single, 2)

    def test_out_degree_callable_nbunch(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n1, self.n3)
        rx_g.add_edge(self.n1, self.n4)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n1, self.n3)
        nx_g.add_edge(self.n1, self.n4)

        # single node call returns int
        rx_single = rx_g.out_degree(self.n1)
        nx_single = nx_g.out_degree(self.n1)
        self.assertEqual(rx_single, nx_single)
        self.assertEqual(rx_single, 3)

    def test_get_edge_data_with_default(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, weight=10)
        nx_g.add_edge(self.n1, self.n2, weight=10)

        rx_data = rx_g.get_edge_data(self.n1, self.n2)
        nx_data = nx_g.get_edge_data(self.n1, self.n2)
        self.assertEqual(rx_data, nx_data)

        default = {"fallback": True}
        rx_default = rx_g.get_edge_data(self.n1, self.n3, default=default)
        nx_default = nx_g.get_edge_data(self.n1, self.n3, default=default)
        self.assertEqual(rx_default, nx_default)
        self.assertEqual(rx_default, default)

    def test_empty_graph_operations(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        self.assertEqual(len(rx_g), len(nx_g))
        self.assertEqual(len(rx_g.nodes), len(nx_g.nodes))
        self.assertEqual(len(rx_g.edges), len(nx_g.edges))
        self.assertEqual(list(rx_g.nodes), list(nx_g.nodes))
        self.assertEqual(list(rx_g.edges), list(nx_g.edges))

        rx_pred = list(rx_g.predecessors(self.n1))
        rx_succ = list(rx_g.successors(self.n1))
        self.assertEqual(rx_pred, [])
        self.assertEqual(rx_succ, [])

    def test_iterate_over_graph_directly(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        rx_nodes = [n for n in rx_g]
        nx_nodes = [n for n in nx_g]

        self.assertEqual(set(rx_nodes), set(nx_nodes))

    def test_nodes_view_equality(self):
        rx_g1 = RxDiGraph()
        rx_g2 = RxDiGraph()

        for n in [self.n1, self.n2, self.n3]:
            rx_g1.add_node(n)
            rx_g2.add_node(n)

        # nodes views should be equal
        self.assertEqual(rx_g1.nodes, rx_g2.nodes)

        # after adding different node, should not be equal
        rx_g2.add_node(self.n4)
        self.assertNotEqual(rx_g1.nodes, rx_g2.nodes)

    def test_add_nodes_from(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        nodes = [self.n1, self.n2, self.n3]
        rx_g.add_nodes_from(nodes)
        nx_g.add_nodes_from(nodes)

        self.assertEqual(set(rx_g.nodes), set(nx_g.nodes))
        self.assertEqual(len(rx_g.nodes), 3)

    def test_remove_nodes_from(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        for n in [self.n1, self.n2, self.n3, self.n4]:
            rx_g.add_node(n)
            nx_g.add_node(n)

        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n3, self.n4)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n3, self.n4)

        rx_g.remove_nodes_from([self.n1, self.n3])
        nx_g.remove_nodes_from([self.n1, self.n3])

        self.assertEqual(set(rx_g.nodes), set(nx_g.nodes))
        self.assertEqual(set(rx_g.nodes), {self.n2, self.n4})

    def test_subgraph(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        rx_g.add_edge(self.n1, self.n2, weight=1)
        rx_g.add_edge(self.n2, self.n3, weight=2)
        rx_g.add_edge(self.n3, self.n4, weight=3)
        rx_g.add_edge(self.n1, self.n3, weight=4)
        nx_g.add_edge(self.n1, self.n2, weight=1)
        nx_g.add_edge(self.n2, self.n3, weight=2)
        nx_g.add_edge(self.n3, self.n4, weight=3)
        nx_g.add_edge(self.n1, self.n3, weight=4)

        rx_sub = rx_g.subgraph([self.n1, self.n2, self.n3])
        nx_sub = nx_g.subgraph([self.n1, self.n2, self.n3]).copy()

        self.assertEqual(set(rx_sub.nodes), set(nx_sub.nodes))
        self.assertEqual(len(rx_sub.nodes), 3)

        rx_edges = set(rx_sub.edges)
        nx_edges = set(nx_sub.edges())
        self.assertEqual(rx_edges, nx_edges)

        self.assertFalse(rx_sub.has_edge(self.n3, self.n4))

        self.assertTrue(rx_sub.has_edge(self.n1, self.n2))
        self.assertTrue(rx_sub.has_edge(self.n2, self.n3))
        self.assertTrue(rx_sub.has_edge(self.n1, self.n3))

        self.assertEqual(rx_sub.get_edge_data(self.n1, self.n2)["weight"], 1)
        self.assertEqual(rx_sub.get_edge_data(self.n1, self.n3)["weight"], 4)

        original_node_count = len(rx_sub.nodes)
        rx_g.add_node(self.n5)
        self.assertEqual(len(rx_sub.nodes), original_node_count)

        rx_sub2 = rx_g.subgraph([self.n1, FakeCFGNode(0x999)])
        self.assertEqual(set(rx_sub2.nodes), {self.n1})

    def test_simple_cycles(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        # create a graph with cycles:
        # n1 -> n2 -> n3 -> n1 (cycle), n2 -> n4
        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n2, self.n3)
        rx_g.add_edge(self.n3, self.n1)
        rx_g.add_edge(self.n2, self.n4)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n3, self.n1)
        nx_g.add_edge(self.n2, self.n4)

        rx_cycles = list(rx_g.simple_cycles())
        nx_cycles = list(networkx.simple_cycles(nx_g))

        self.assertEqual(len(rx_cycles), len(nx_cycles))
        self.assertEqual(len(rx_cycles), 1)

        rx_cycle_set = set(rx_cycles[0])
        nx_cycle_set = set(nx_cycles[0])
        self.assertEqual(rx_cycle_set, nx_cycle_set)
        self.assertEqual(rx_cycle_set, {self.n1, self.n2, self.n3})

    def test_simple_cycles_no_cycles(self):
        rx_g = RxDiGraph()
        nx_g = networkx.DiGraph()

        # no cycles
        rx_g.add_edge(self.n1, self.n2)
        rx_g.add_edge(self.n2, self.n3)
        nx_g.add_edge(self.n1, self.n2)
        nx_g.add_edge(self.n2, self.n3)

        rx_cycles = list(rx_g.simple_cycles())
        nx_cycles = list(networkx.simple_cycles(nx_g))

        self.assertEqual(len(rx_cycles), 0)
        self.assertEqual(len(nx_cycles), 0)


if __name__ == "__main__":
    unittest.main()
