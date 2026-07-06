#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""
Regression tests for DirectedGraphHelper, the node-order / postorder cache that PhoenixStructurer keeps in sync
with the region graph. Each test corresponds to a bug that made the cache go stale and crashed the decompiler
with a KeyError in `replace_nodes`.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.utils.graph import DirectedGraphHelper


class _Node:
    """A minimal graph node with an address, mimicking AIL blocks / structurer nodes."""

    __slots__ = ("addr",)

    def __init__(self, addr: int):
        self.addr = addr

    def __repr__(self):
        return f"N({self.addr:#x})"


def _make_helper(edges, head, cyclic=False):
    g = networkx.DiGraph(edges)
    return g, DirectedGraphHelper(g, cyclic, head)


def _linked_list_values(helper):
    values = []
    llnode = helper._postorder_node_to_llnode and helper._postorder_node_head
    while llnode is not None:
        values.append(llnode.v)
        llnode = llnode.next
    return values


class TestPostorderCacheGeneration(unittest.TestCase):
    """The postorder cache must cover every node of the graph, not only nodes reachable from the head."""

    def test_unreachable_nodes_are_cached(self):
        # nodes 4 and 5 are not reachable from the head; they used to be missing from the cache, so a later
        # replace_nodes() on them raised KeyError
        _, helper = _make_helper([(1, 2), (2, 3), (4, 5)], head=1)

        order = list(helper.dfs_postorder_nodes_deterministic(1))
        # iteration-until-head semantics are unchanged: unreachable nodes are appended after the head and thus
        # never yielded when iterating up to the head
        assert order == [3, 2, 1]
        assert set(helper._postorder_node_to_llnode) == {1, 2, 3, 4, 5}

        helper.replace_nodes(4, 5, 45)  # must not raise
        assert 45 in helper._postorder_node_to_llnode
        # and the merge must not have invalidated the cache
        assert helper._postorder_node_to_llnode is not None
        assert list(helper.dfs_postorder_nodes_deterministic(1)) == [3, 2, 1]

    def test_marked_edges_hide_head_out_edges(self):
        # the real-world trigger (tar sub_529cb0): after cyclic refinement marks the head's only out-edge with
        # cyclic_refinement_outgoing, the head becomes a sink in the filtered region view that the graph helper
        # traverses, so the cache used to cover only the head itself; matching a cyclic while against the loop
        # body then crashed with KeyError in replace_nodes
        h, a, b, c, d = (_Node(x) for x in (0x10, 0x20, 0x30, 0x40, 0x50))
        shared = networkx.DiGraph([(h, a), (a, b), (a, c), (b, a), (b, d), (d, h)])
        mgr = OverlayManager(shared)
        region = mgr.root.create_subregion(h, {h, a, b, c, d}, cyclic=True)
        region.mark_edge(h, a, cyclic_refinement_outgoing=True)

        # this is exactly how PhoenixStructurer._analyze() initializes the helper
        helper = DirectedGraphHelper(region.graph_with_successors, True, h)

        # the head is a sink in the filtered view: iterating up to the head yields the head only
        assert list(helper.dfs_postorder_nodes_deterministic(h)) == [h]
        # but the cache must still cover the whole graph
        assert set(helper._postorder_node_to_llnode) == {h, a, b, c, d}

        # what _match_cyclic_while does when merging the loop body: this used to raise KeyError
        loop_node = _Node(0x20)
        helper.replace_nodes(a, b, loop_node)
        cached = set(helper._postorder_node_to_llnode)
        assert loop_node in cached
        assert a not in cached
        assert b not in cached


class TestReplaceNodesAliasing(unittest.TestCase):
    """replace_nodes() must survive new_node being the same object as one of the old nodes (in-place absorption,
    as done by _match_acyclic_sequence with an IncompleteSwitchCaseNode successor)."""

    def test_new_node_is_old_node_1(self):
        _, helper = _make_helper([(1, 2), (2, 3), (3, 4)], head=1)
        list(helper.dfs_postorder_nodes_deterministic(1))

        helper.replace_nodes(2, 3, 3)
        # node 3 used to be evicted from the cache here (popped after insertion), making the very next
        # replace involving it crash
        assert 3 in helper._postorder_node_to_llnode
        assert 2 not in helper._postorder_node_to_llnode
        assert list(helper.dfs_postorder_nodes_deterministic(1)) == [4, 3, 1]

    def test_new_node_is_old_node_0(self):
        _, helper = _make_helper([(1, 2), (2, 3), (3, 4)], head=1)
        list(helper.dfs_postorder_nodes_deterministic(1))

        helper.replace_nodes(2, 3, 2)
        assert 2 in helper._postorder_node_to_llnode
        assert 3 not in helper._postorder_node_to_llnode
        assert list(helper.dfs_postorder_nodes_deterministic(1)) == [4, 2, 1]

    def test_unlinking_the_list_head(self):
        # postorder of 1 -> 2 is [2, 1]: node 2 is the first linked-list node. merging (1, 2) must move the
        # list head to the merged node instead of leaving it on the unlinked node
        _, helper = _make_helper([(1, 2)], head=1)
        list(helper.dfs_postorder_nodes_deterministic(1))

        helper.replace_nodes(1, 2, 99)
        assert _linked_list_values(helper) == [99]

    def test_remove_node_updates_list_head(self):
        _, helper = _make_helper([(1, 2), (1, 3)], head=1)
        postorder = list(helper.dfs_postorder_nodes_deterministic(1))

        helper.remove_node(postorder[0])
        assert _linked_list_values(helper) == postorder[1:]


class TestStaleCacheLastResort(unittest.TestCase):
    """A cache update that references an unknown node signals a bug in the caller, but it must degrade to
    invalidate-and-regenerate instead of KeyError / AssertionError / silent corruption."""

    def test_replace_node_with_stale_node_invalidates(self):
        _, helper = _make_helper([(1, 2), (2, 3)], head=1)
        list(helper.dfs_postorder_nodes_deterministic(1))

        helper.replace_node(99, 100)  # 99 was never in the graph
        assert helper._postorder_node_to_llnode is None
        # the cache regenerates transparently on the next query
        assert list(helper.dfs_postorder_nodes_deterministic(1)) == [3, 2, 1]

    def test_replace_nodes_with_stale_node_invalidates(self):
        _, helper = _make_helper([(1, 2), (2, 3)], head=1)
        list(helper.dfs_postorder_nodes_deterministic(1))

        helper.replace_nodes(99, 100, 101)  # must not raise KeyError
        assert helper._postorder_node_to_llnode is None
        assert list(helper.dfs_postorder_nodes_deterministic(1)) == [3, 2, 1]

    def test_add_node_successor_with_stale_node_invalidates(self):
        _, helper = _make_helper([(1, 2), (2, 3)], head=1)
        list(helper.dfs_postorder_nodes_deterministic(1))

        helper.add_node_successor(99, 100)  # used to fail an assertion
        assert helper._postorder_node_to_llnode is None
        assert list(helper.dfs_postorder_nodes_deterministic(1)) == [3, 2, 1]

    def test_replace_node_does_not_corrupt_node_order(self):
        # the node order cache used to silently assign order 0 to the new node when the old node was unknown
        # (dict.pop(old, 0)), breaking sort_nodes_by_order for every later query
        g = networkx.DiGraph([(1, 2), (2, 3), (3, 1)])
        helper = DirectedGraphHelper(g, True, 1)
        assert helper.loop_heads() == {1}  # generates the node order

        helper.replace_node(99, 100)
        assert helper._node_order is None
        assert helper.sort_nodes_by_order([3, 1, 2]) == [1, 2, 3]

    def test_add_node_successor_with_stale_node_invalidates_node_order(self):
        g = networkx.DiGraph([(1, 2), (2, 3), (3, 1)])
        helper = DirectedGraphHelper(g, True, 1)
        helper.loop_heads()

        helper.add_node_successor(99, 100)  # used to fail an assertion
        assert helper._node_order is None
        assert helper.sort_nodes_by_order([2, 1]) == [1, 2]

    def test_sort_nodes_by_order_regenerates_for_unknown_nodes(self):
        g = networkx.DiGraph([(1, 2), (2, 3), (3, 1)])
        helper = DirectedGraphHelper(g, True, 1)
        helper.loop_heads()

        # a node added to the graph behind the helper's back used to raise KeyError when sorted
        g.add_edge(3, 4)
        assert helper.sort_nodes_by_order([4, 2, 1]) == [1, 2, 4]

    def test_loop_heads_regenerates_for_unknown_nodes(self):
        g = networkx.DiGraph([(1, 2), (2, 3), (3, 1)])
        helper = DirectedGraphHelper(g, True, 1)
        assert helper.loop_heads() == {1}

        g.add_edge(3, 4)
        assert helper.loop_heads() == {1}  # used to raise KeyError on the (3, 4) edge


if __name__ == "__main__":
    unittest.main()
