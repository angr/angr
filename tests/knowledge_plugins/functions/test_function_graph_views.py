#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""
Function.transition_graph and Function.graph are read-only networkx views: the whole DiGraph read API and the
networkx algorithms work on them, every write is rejected, and every copy is a detached, mutable networkx graph.
"""

from __future__ import annotations

import copy
import os
import pickle
import unittest

import networkx

import angr
from angr.codenode import BlockNode, FuncNode
from angr.knowledge_plugins.functions.transition_graph import ReadOnlyAttrDict, ReadOnlyGraphError, TransitionGraph
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


class TestFunctionGraphViews(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.proj.analyses.CFGFast(normalize=True)
        cls.main = cls.proj.kb.functions["main"]

    def _views(self):
        return self.main.transition_graph, self.main.graph

    def test_read_api(self):
        for view in self._views():
            assert isinstance(view, TransitionGraph) and isinstance(view, networkx.DiGraph)
            assert networkx.is_frozen(view)
            assert view.is_directed() and not view.is_multigraph()
            nodes = list(view.nodes)
            assert nodes and set(view.nodes()) == set(nodes) and set(view) == set(nodes)
            assert len(view) == view.number_of_nodes() == len(nodes) == view.order()
            assert all(d == {} and isinstance(d, ReadOnlyAttrDict) for _, d in view.nodes(data=True))
            edges = list(view.edges)
            assert edges and list(view.edges()) == edges
            assert view.number_of_edges() == len(edges) == view.size()
            start = self.main.startpoint
            assert start in view and view.has_node(start) and not view.has_node(FuncNode(1))
            for u, v, d in view.edges(data=True):
                assert isinstance(d, ReadOnlyAttrDict) and "type" in d
                assert view.has_edge(u, v) and (u, v) in view.edges
                assert view.get_edge_data(u, v) is d
                assert view[u][v] is d and view.adj[u][v] is d and view.succ[u][v] is d and view.pred[v][u] is d
                assert view.edges[u, v] is d
                assert v in view.successors(u) and v in view.neighbors(u) and u in view.predecessors(v)
                assert view.has_successor(u, v) and view.has_predecessor(v, u)
                assert (u, v) in view.out_edges(u) and (u, v) in view.in_edges(v)
                assert (u, v, d) in view.out_edges(u, data=True) and (u, v, d) in view.in_edges(v, data=True)
            assert view.get_edge_data(start, FuncNode(1)) is None
            for n in nodes:
                assert view.out_degree(n) == view.out_degree[n] == len(list(view.successors(n)))
                assert view.in_degree(n) == view.in_degree[n] == len(list(view.predecessors(n)))
                assert view.degree(n) == view.degree[n] == view.in_degree(n) + view.out_degree(n)
            assert dict(view.out_degree) == {n: view.out_degree(n) for n in nodes}
            assert set(view.nbunch_iter([start, FuncNode(1)])) == {start}
            assert dict(view.adjacency())[start] == dict(view.adj[start])
            # views of the view are read-only too
            sub = view.subgraph([start, *view.successors(start)])
            assert start in sub and networkx.is_frozen(sub)
            esub = view.edge_subgraph(list(view.out_edges(start)))
            assert set(esub.edges) == set(view.out_edges(start))
            rev = view.reverse(copy=False)
            assert set(rev.edges) == {(v, u) for u, v in edges}
            assert set(view.copy(as_view=True).edges) == set(edges)
            assert set(view.to_undirected(as_view=True).edges) and set(view.to_directed(as_view=True).edges) == set(
                edges
            )
            # algorithms
            assert networkx.descendants(view, start) == set(nodes) - {start} - {
                n for n in nodes if not networkx.has_path(view, start, n)
            }
            assert networkx.ancestors(view, start) == {
                n for n in nodes if n != start and networkx.has_path(view, n, start)
            }
            assert next(iter(networkx.dfs_preorder_nodes(view, start))) is start
            assert set(networkx.bfs_tree(view, start).nodes) <= set(nodes)
            dominators = networkx.immediate_dominators(view, start)
            assert start not in dominators and all(dominators[n] in view for n in dominators)
            assert all(
                dominators[n] is start for n in view.successors(start) if n in dominators and view.in_degree(n) == 1
            )
            sccs = list(networkx.strongly_connected_components(view))
            assert sum(len(c) for c in sccs) == len(nodes)
            cycles = list(networkx.simple_cycles(view))
            assert all(isinstance(c, list) for c in cycles)
            if networkx.is_directed_acyclic_graph(view):
                assert next(iter(networkx.topological_sort(view))) is start
            target = next(n for n in nodes if n is not start and networkx.has_path(view, start, n))
            path = networkx.shortest_path(view, start, target)
            assert path[0] is start and path[-1] is target
            assert networkx.number_weakly_connected_components(view) >= 1

    @staticmethod
    def _mutations(view, start, succ, node):
        edge_data = next(d for _, _, d in view.edges(data=True))
        return [
            lambda: view.add_node(node),
            lambda: view.add_nodes_from([node]),
            lambda: view.add_edge(start, node),
            lambda: view.add_edges_from([(start, node)]),
            lambda: view.add_weighted_edges_from([(start, node, 1)]),
            lambda: view.remove_node(start),
            lambda: view.remove_nodes_from([start]),
            lambda: view.remove_edge(start, succ),
            lambda: view.remove_edges_from([(start, succ)]),
            view.clear,
            view.clear_edges,
            lambda: view.update(edges=[(start, node)]),
            lambda: view.graph.__setitem__("name", "x"),
            lambda: view.graph.update(name="x"),
            lambda: view.nodes[start].__setitem__("x", 1),
            lambda: view[start][succ].__setitem__("confirmed", True),
            lambda: view.edges[start, succ].__delitem__("type"),
            lambda: view.edges[start, succ].pop("type"),
            lambda: view.edges[start, succ].setdefault("x", 1),
            view.edges[start, succ].clear,
            lambda: edge_data.update(x=1),
        ]

    def test_writes_are_rejected(self):
        func = self.main
        blob_before = func._graph.to_bytes()
        node = FuncNode(0xDEAD)
        start = func.startpoint
        for view in self._views():
            succ = next(iter(view.successors(start)))
            func._dirty = False
            calls = self._mutations(view, start, succ, node)
            for call in calls:
                with self.assertRaises(networkx.NetworkXError) as cm:
                    call()
                assert isinstance(cm.exception, ReadOnlyGraphError)
                assert "read-only view of Function.transition_graph" in str(cm.exception)
            assert not func.dirty
            assert func._graph.to_bytes() == blob_before
            assert node not in view and start in view and view.has_edge(start, succ)

    def test_copies_are_detached_and_mutable(self):
        func = self.main
        node = FuncNode(0xDEAD)
        for view in self._views():
            edges = set(view.edges)
            for g in (
                view.copy(),
                view.reverse(copy=True),
                view.to_directed(),
                networkx.DiGraph(view),
                view.subgraph(list(view.nodes)).copy(),
                pickle.loads(pickle.dumps(view)),
                copy.deepcopy(view),
            ):
                assert type(g) is networkx.DiGraph and not networkx.is_frozen(g)
                expected = {(v, u) for u, v in edges} if g is not None and set(g.edges) != edges else edges
                assert set(g.edges) == expected
                g.add_node(node)
                g.add_edge(node, node, type="transition")
                u, v = next(iter(edges))
                d = g[u][v] if g.has_edge(u, v) else g[v][u]
                assert type(d) is dict
                d["confirmed"] = "changed"
                g.remove_node(node)
                g.clear()
            und = view.to_undirected()
            assert type(und) is networkx.Graph
            und.add_node(node)
            assert node not in view
            assert set(view.edges) == edges
            for _, _, d in view.edges(data=True):
                assert d.get("confirmed") != "changed"
        # pickling a Function goes through the store, not the view
        _ = func.transition_graph
        unpickled = pickle.loads(pickle.dumps(func))
        assert unpickled._tg is None
        assert {(u.addr, v.addr) for u, v in unpickled.transition_graph.edges} == {
            (u.addr, v.addr) for u, v in func.transition_graph.edges
        }

    def test_function_api_keeps_the_views_current(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        func = proj.kb.functions.function(0x40071D, create=True)
        assert func is not None
        a = BlockNode(0x40071D, 4)
        b = BlockNode(0x400721, 8)
        func._register_node(True, a)
        tg = func.transition_graph
        local = func.graph
        func._add_graph_edge(a, b, type="fake_return", outside=False)
        assert tg[a][b] == {"type": "fake_return", "outside": False}
        assert func.graph is not local and func.graph.has_edge(a, b)
        func._set_edge_confirmed(a, b, True)
        assert tg[a][b]["confirmed"] is True
        func._set_edge_outside(a, b, True)
        assert tg[a][b]["outside"] is True and not func.graph.has_edge(a, b)
        func._remove_edge(a, b)
        assert not tg.has_edge(a, b)
        with self.assertRaises(networkx.NetworkXError):
            func._remove_edge(a, b)
        func._remove_graph_node(b)
        assert b not in tg
        with self.assertRaises(networkx.NetworkXError):
            func._remove_graph_node(b)
        # graph_ex returns a mutable copy that does not touch the cached view
        g = func.graph_ex()
        assert type(g) is networkx.DiGraph
        g.add_node(b)
        assert b not in func.graph


if __name__ == "__main__":
    unittest.main()
