#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.analyses.decompiler.graph_region import GraphRegion
from angr.analyses.decompiler.region_overlay import OverlayManager


class Node:
    def __init__(self, n):
        self.n = n

    @property
    def addr(self):
        return self.n

    def __repr__(self):
        return f"<Node {self.n}>"


def diamond():
    """1 -> 2 -> {3, 4} -> 5 -> 6, returns (graph, nodes-by-index)."""
    nodes = {i: Node(i) for i in range(1, 7)}
    g = networkx.DiGraph()
    g.add_edges_from(
        [
            (nodes[1], nodes[2], {"type": "transition"}),
            (nodes[2], nodes[3], {}),
            (nodes[2], nodes[4], {}),
            (nodes[3], nodes[5], {}),
            (nodes[4], nodes[5], {}),
            (nodes[5], nodes[6], {}),
        ]
    )
    return g, nodes


def edge_set(graph):
    return set(graph.edges())


class TestRegionOverlayViews(unittest.TestCase):
    def test_flat_root(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]

        assert set(mgr.root.members) == set(n.values())
        assert mgr.root.successor_nodes() == set()
        view = mgr.root.view()
        assert set(view.nodes) == set(n.values())
        assert edge_set(view) == edge_set(g)
        # edge data passes through
        assert view[n[1]][n[2]]["type"] == "transition"
        # the with-successors view of the root equals the member view
        assert edge_set(mgr.root.view_with_successors()) == edge_set(g)

    def test_subregion_views(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        assert sub.successor_nodes() == {n[6]}
        assert set(sub.view().nodes) == {n[2], n[3], n[4], n[5]}
        assert (n[5], n[6]) not in edge_set(sub.view())
        gws = sub.view_with_successors()
        assert set(gws.nodes) == {n[2], n[3], n[4], n[5], n[6]}
        assert (n[5], n[6]) in edge_set(gws)
        # external in-edge of the head is invisible in both views
        assert n[1] not in gws

        # parent view shows the subregion as a single node
        root_view = mgr.root.view()
        assert set(root_view.nodes) == {n[1], sub, n[6]}
        assert edge_set(root_view) == {(n[1], sub), (sub, n[6])}
        # quotient in-edge keeps underlying edge data
        assert root_view[n[1]][sub]["type"] == "transition"

        # GraphRegion-compatible properties
        assert isinstance(sub, GraphRegion)
        assert sub.graph is sub.view()
        assert sub.successors == {n[6]}
        assert sub.addr == 2

    def test_nested_subregions(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        outer = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        inner = outer.create_subregion(n[3], [n[3], n[5]], cyclic=False)

        assert inner.parent is outer
        assert outer.children == [inner]
        assert mgr.owner_of(n[3]) is inner
        assert mgr.owner_of(n[2]) is outer

        # inner region: successor 6 is found through the ancestor chain
        assert inner.successor_nodes() == {n[6]}
        # outer region view: inner is a single node; two underlying edges (2->3 via inner, 4->5 via inner)
        outer_view = outer.view()
        assert set(outer_view.nodes) == {n[2], n[4], inner}
        assert edge_set(outer_view) == {(n[2], inner), (n[2], n[4]), (n[4], inner)}
        # outer successors derived through inner's nodes
        assert outer.successor_nodes() == {n[6]}
        assert (inner, n[6]) in edge_set(outer.view_with_successors())
        # root sees only the outer region
        assert set(mgr.root.view().nodes) == {n[1], outer, n[6]}

    def test_cyclic_region_no_self_loop_in_parent(self):
        nodes = {i: Node(i) for i in range(1, 5)}
        g = networkx.DiGraph()
        g.add_edges_from([(nodes[1], nodes[2]), (nodes[2], nodes[3]), (nodes[3], nodes[2]), (nodes[3], nodes[4])])
        mgr = OverlayManager(g)
        mgr.root.head = nodes[1]
        loop = mgr.root.create_subregion(nodes[2], [nodes[2], nodes[3]], cyclic=True)

        assert edge_set(loop.view()) == {(nodes[2], nodes[3]), (nodes[3], nodes[2])}
        assert loop.successor_nodes() == {nodes[4]}
        root_view = mgr.root.view()
        # the loop's internal back edge must not become a self-loop on the region node
        assert edge_set(root_view) == {(nodes[1], loop), (loop, nodes[4])}


class TestRegionOverlayMutation(unittest.TestCase):
    def test_replace_nodes_rewires_external_edges(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        seq = Node(0x20)
        sub.replace_nodes(n[2], seq, old_node_1=n[3])
        assert sub.head is seq
        assert set(sub.members) == {seq, n[4], n[5]}
        # the external in-edge 1 -> 2 has been rewired to the new node in the shared graph
        assert g.has_edge(n[1], seq)
        assert n[2] not in g and n[3] not in g
        assert mgr.owner_of(seq) is sub
        # the parent view still shows a single region node with the same connectivity
        assert edge_set(mgr.root.view()) == {(n[1], sub), (sub, n[6])}
        assert edge_set(sub.view()) == {(seq, n[4]), (seq, n[5]), (n[4], n[5])}

    def test_hide_vs_detach(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        sub.hide_edge(n[5], n[6])
        assert sub.successor_nodes() == set()
        assert n[6] not in sub.view_with_successors()
        # the parent still sees the region exit
        assert (sub, n[6]) in edge_set(mgr.root.view())
        assert g.has_edge(n[5], n[6])

        sub.detach_edge(n[5], n[6])
        assert not g.has_edge(n[5], n[6])
        assert (sub, n[6]) not in edge_set(mgr.root.view())

    def test_remove_successor_node_is_intercepted(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        sub.remove_node(n[6])  # n[6] is a successor: must only be hidden from this region's views
        assert sub.successor_nodes() == set()
        assert n[6] in g
        assert (sub, n[6]) in edge_set(mgr.root.view())

    def test_remove_member_node(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        sub.remove_node(n[4])
        assert n[4] not in g
        assert mgr.owner_of(n[4]) is None
        assert set(sub.members) == {n[2], n[3], n[5]}
        assert n[4] not in sub.underlying_nodes()

    def test_add_edge_to_region_destination_resolves_to_entry(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        new = Node(0x10)
        mgr.root.add_node(new)
        mgr.root.add_edge(new, sub)
        assert g.has_edge(new, n[2])
        assert (new, sub) in edge_set(mgr.root.view())


class TestRegionOverlayLifecycle(unittest.TestCase):
    def _structure_to_single_node(self, sub, n):
        n1 = Node(0x21)
        sub.replace_nodes(n[2], n1, old_node_1=n[3])
        n2 = Node(0x22)
        sub.replace_nodes(n1, n2, old_node_1=n[4])
        n3 = Node(0x23)
        sub.replace_nodes(n2, n3, old_node_1=n[5])
        return n3

    def test_finalize(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        result = self._structure_to_single_node(sub, n)
        assert set(sub.members) == {result}
        sub.finalize(result)

        assert sub.replacement is result
        assert mgr.owner_of(result) is mgr.root
        assert sub not in mgr.root.children
        assert set(mgr.root.members) == {n[1], result, n[6]}
        assert edge_set(mgr.root.view()) == {(n[1], result), (result, n[6])}

    def test_finalize_updates_parent_head(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        sub = mgr.root.create_subregion(n[1], [n[1], n[2], n[3], n[4], n[5]], cyclic=False)
        mgr.root.head = sub

        m1 = Node(0x31)
        sub.replace_nodes(n[1], m1, old_node_1=n[2])
        m2 = Node(0x32)
        sub.replace_nodes(m1, m2, old_node_1=n[3])
        m3 = Node(0x33)
        sub.replace_nodes(m2, m3, old_node_1=n[4])
        m4 = Node(0x34)
        sub.replace_nodes(m3, m4, old_node_1=n[5])
        sub.finalize(m4)
        assert mgr.root.head is m4

    def test_dissolve(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        sub.hide_edge(n[3], n[5])

        sub.dissolve()
        assert sub not in mgr.root.children
        assert set(mgr.root.members) == set(n.values())
        assert mgr.owner_of(n[2]) is mgr.root
        # edges hidden in the dissolved region stay hidden in the parent
        assert (n[3], n[5]) not in edge_set(mgr.root.view())
        assert g.has_edge(n[3], n[5])

    def test_undo_rollback(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        before_edges = set(g.edges())
        before_members = set(sub.members)
        before_view = edge_set(sub.view())
        before_owner = dict(mgr._owner)

        chk = mgr.checkpoint()
        seq = Node(0x40)
        sub.replace_nodes(n[2], seq, old_node_1=n[3])
        sub.detach_edge(n[4], n[5])
        sub.hide_edge(seq, n[5])
        inner = sub.create_subregion(n[4], [n[4]], cyclic=False)
        assert set(sub.members) != before_members
        mgr.rollback(chk)

        assert set(g.edges()) == before_edges
        assert set(sub.members) == before_members
        assert edge_set(sub.view()) == before_view
        assert dict(mgr._owner) == before_owner
        assert sub.head is n[2]
        assert inner not in sub.children

    def test_undo_rollback_finalize_and_dissolve(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        chk = mgr.checkpoint()
        n1 = Node(0x21)
        sub.replace_nodes(n[2], n1, old_node_1=n[3])
        n2 = Node(0x22)
        sub.replace_nodes(n1, n2, old_node_1=n[4])
        n3 = Node(0x23)
        sub.replace_nodes(n2, n3, old_node_1=n[5])
        sub.finalize(n3)
        mgr.rollback(chk)

        assert sub in mgr.root.children
        assert sub.replacement is None
        assert set(sub.members) == {n[2], n[3], n[4], n[5]}
        assert mgr.owner_of(n[2]) is sub
        assert edge_set(sub.view()) == {(n[2], n[3]), (n[2], n[4]), (n[3], n[5]), (n[4], n[5])}

        chk2 = mgr.checkpoint()
        sub.dissolve()
        mgr.rollback(chk2)
        assert sub in mgr.root.children
        assert set(sub.members) == {n[2], n[3], n[4], n[5]}
        assert mgr.owner_of(n[3]) is sub


class TestGraphRegionConversion(unittest.TestCase):
    def test_copy_returns_plain_graph_region(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)

        region = sub.copy()
        assert type(region) is GraphRegion
        assert region.head is n[2]
        assert set(region.graph.nodes) == {n[2], n[3], n[4], n[5]}
        assert region.successors == {n[6]}
        assert (n[5], n[6]) in region.graph_with_successors.edges
        # mutating the copy does not affect the overlay
        region.graph.remove_node(n[4])
        assert n[4] in sub.view()

    def test_recursive_copy_builds_graph_region_tree(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        outer = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        inner = outer.create_subregion(n[3], [n[3], n[5]], cyclic=False)

        tree = mgr.root.recursive_copy()
        assert type(tree) is GraphRegion
        assert tree.successors is None and tree.graph_with_successors is None
        outer_r = next(x for x in tree.graph.nodes if isinstance(x, GraphRegion))
        assert type(outer_r) is GraphRegion and outer_r is not outer
        assert tree.head is n[1]
        assert set(tree.graph.nodes) == {n[1], outer_r, n[6]}

        inner_r = next(x for x in outer_r.graph.nodes if isinstance(x, GraphRegion))
        assert type(inner_r) is GraphRegion and inner_r is not inner
        assert outer_r.head is n[2]
        assert inner_r.head is n[3]
        assert inner_r.successors == {n[6]}
        assert outer_r.successors == {n[6]}
        assert (inner_r, n[6]) in outer_r.graph_with_successors.edges

    def test_successor_successor_edges_inside_loops(self):
        nodes = {i: Node(i) for i in range(1, 8)}
        g = networkx.DiGraph()
        # 1 -> 2 -> {3, 4}, 3 -> 4 (an edge between two successors of region {2})
        g.add_edges_from([(nodes[1], nodes[2]), (nodes[2], nodes[3]), (nodes[2], nodes[4]), (nodes[3], nodes[4])])
        mgr = OverlayManager(g)
        mgr.root.head = nodes[1]
        # inside a loop, edges between successors are part of the with-successors view
        sub = mgr.root.create_subregion(nodes[2], [nodes[2]], cyclic=False, cyclic_ancestor=True)
        assert sub.successor_nodes() == {nodes[3], nodes[4]}
        assert (nodes[3], nodes[4]) in edge_set(sub.view_with_successors())

        # outside loops, successor-successor edges are not included (matching RegionIdentifier)
        mgr2 = OverlayManager(networkx.DiGraph(g))
        sub2 = mgr2.root.create_subregion(nodes[2], [nodes[2]], cyclic=False)
        assert sub2.successor_nodes() == {nodes[3], nodes[4]}
        assert (nodes[3], nodes[4]) not in edge_set(sub2.view_with_successors())


if __name__ == "__main__":
    unittest.main()


class TestRegionOverlayGraph(unittest.TestCase):
    def _assert_equivalent(self, rog, materialized):
        assert set(rog.nodes) == set(materialized.nodes)
        assert set(rog.edges) == set(materialized.edges)
        for n in materialized.nodes:
            assert rog.in_degree[n] == materialized.in_degree[n], n
            assert rog.out_degree[n] == materialized.out_degree[n], n
            assert set(rog.successors(n)) == set(materialized.successors(n))
            assert set(rog.predecessors(n)) == set(materialized.predecessors(n))
        assert len(rog) == len(materialized)
        assert rog.number_of_nodes() == materialized.number_of_nodes()

    def _fixtures(self):
        """Yield (overlay, description) pairs covering the existing view fixtures."""
        # diamond with a flat subregion
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        yield sub, "diamond-sub"
        yield mgr.root, "diamond-root"

        # nested subregions
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        outer = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        inner = outer.create_subregion(n[3], [n[3], n[5]], cyclic=False)
        yield inner, "nested-inner"
        yield outer, "nested-outer"
        yield mgr.root, "nested-root"

        # cyclic region with successor-successor edge potential
        nodes = {i: Node(i) for i in range(1, 6)}
        g2 = networkx.DiGraph()
        g2.add_edges_from(
            [
                (nodes[1], nodes[2]),
                (nodes[2], nodes[3]),
                (nodes[3], nodes[2]),
                (nodes[3], nodes[4]),
                (nodes[3], nodes[5]),
                (nodes[4], nodes[5]),
            ]
        )
        mgr2 = OverlayManager(g2)
        mgr2.root.head = nodes[1]
        loop = mgr2.root.create_subregion(nodes[2], [nodes[2], nodes[3]], cyclic=True)
        yield loop, "cyclic"

        # region with hidden edges
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        sub.hide_edge(n[3], n[5])
        sub.hide_edge(n[5], n[6])
        yield sub, "hidden"

    def test_equivalence_with_materialized_views(self):
        for overlay, desc in self._fixtures():
            for full in (False, True):
                rog = overlay.view_graph(full=full)
                materialized = overlay.view_with_successors() if full else overlay.view()
                try:
                    self._assert_equivalent(rog, materialized)
                except AssertionError as ex:
                    raise AssertionError(f"fixture {desc} full={full}: {ex}") from ex

    def test_networkx_algorithm_smoke(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        rog = sub.view_graph()
        full = sub.view_graph(full=True)

        from angr.utils.graph import GraphUtils, dfs_back_edges

        assert networkx.is_directed_acyclic_graph(rog)
        assert networkx.descendants(rog, n[2]) == {n[3], n[4], n[5]}
        assert networkx.has_path(rog, n[2], n[5])
        assert set(networkx.dfs_postorder_nodes(rog, n[2])) == {n[2], n[3], n[4], n[5]}
        assert list(GraphUtils.dfs_postorder_nodes_deterministic(rog, n[2]))[-1] is n[2]
        order = GraphUtils.quasi_topological_sort_nodes(rog)
        assert order.index(n[2]) < order.index(n[5])
        assert not list(dfs_back_edges(rog, n[2]))
        assert networkx.immediate_dominators(rog, n[2])[n[5]] is n[2]
        assert list(networkx.strongly_connected_components(rog))
        assert dict(networkx.bfs_successors(rog, n[2]))
        # constructing a real DiGraph from the view
        copied = networkx.DiGraph(full)
        assert set(copied.edges) == set(full.edges)
        # dfs_tree and subgraph
        assert set(networkx.dfs_tree(rog, n[2]).nodes) == {n[2], n[3], n[4], n[5]}
        assert set(networkx.subgraph(rog, [n[2], n[3]]).nodes) == {n[2], n[3]}
        # mutations are frozen
        try:
            rog.add_node(Node(99))
            raise AssertionError("expected frozen graph")
        except networkx.NetworkXError:
            pass

    def test_cyclic_region_view_graph(self):
        nodes = {i: Node(i) for i in range(1, 5)}
        g = networkx.DiGraph()
        g.add_edges_from([(nodes[1], nodes[2]), (nodes[2], nodes[3]), (nodes[3], nodes[2]), (nodes[3], nodes[4])])
        mgr = OverlayManager(g)
        mgr.root.head = nodes[1]
        loop = mgr.root.create_subregion(nodes[2], [nodes[2], nodes[3]], cyclic=True)
        rog = loop.view_graph()
        assert not networkx.is_directed_acyclic_graph(rog)
        from angr.utils.graph import dfs_back_edges

        assert list(dfs_back_edges(rog, nodes[2]))

    def test_marks_filtering(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        sub.edge_marks.add((n[3], n[5]))

        rog = sub.view_graph()
        assert not rog.has_edge(n[3], n[5])
        assert (n[3], n[5]) not in set(rog.edges)
        assert rog.out_degree[n[3]] == 0
        assert rog.edge_marked(n[3], n[5])
        # all_edges variants include the marked edge
        assert rog.has_edge(n[3], n[5], all_edges=True)
        assert rog.with_all_edges().has_edge(n[3], n[5])
        assert set(rog.with_all_edges().successors(n[3])) == {n[5]}
        # the underlying shared graph data is untouched
        assert g.has_edge(n[3], n[5])

    def test_to_acyclic(self):
        nodes = {i: Node(i) for i in range(1, 5)}
        g = networkx.DiGraph()
        g.add_edges_from([(nodes[1], nodes[2]), (nodes[2], nodes[3]), (nodes[3], nodes[2]), (nodes[3], nodes[4])])
        mgr = OverlayManager(g)
        mgr.root.head = nodes[1]
        loop = mgr.root.create_subregion(nodes[2], [nodes[2], nodes[3]], cyclic=True)
        rog = loop.view_graph()
        acyclic = rog.to_acyclic([(nodes[3], nodes[2])])
        assert networkx.is_directed_acyclic_graph(acyclic)
        assert not acyclic.has_edge(nodes[3], nodes[2])
        assert acyclic.has_edge(nodes[2], nodes[3])
        # the source view is unaffected
        assert rog.has_edge(nodes[3], nodes[2])

    def test_full_view_and_kwargs(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        rog = sub.view_graph()
        assert n[6] not in rog
        assert n[6] in rog.full_view
        assert rog.full_view.has_edge(n[5], n[6])
        assert rog.has_edge(n[5], n[6], fullgraph=True)
        assert set(rog.successors(n[5], fullgraph=True)) == {n[6]}
        assert set(rog.successors(n[5])) == set()
        assert rog.full_view.member_view is rog
        # hidden-full hides from the full view only
        sub._hidden_full.add((n[5], n[6]))
        assert not rog.full_view.has_edge(n[5], n[6])
        assert n[6] in rog.full_view  # the node is still a successor
        sub._hidden_full.clear()

    def test_materialize_independence(self):
        g, n = diamond()
        mgr = OverlayManager(g)
        mgr.root.head = n[1]
        sub = mgr.root.create_subregion(n[2], [n[2], n[3], n[4], n[5]], cyclic=False)
        rog = sub.view_graph()
        m = rog.materialize()
        m.remove_node(n[4])
        assert n[4] in rog
        assert g.has_edge(n[2], n[4])
