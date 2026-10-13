# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

from unittest import TestCase, main

import networkx

from angr.utils.graph import DirectedGraphHelper


class TestDirectedGraphHelper(TestCase):
    def test_node_order_follows_graph_changes(self):
        # 0 -> 1 -> 2 -> 3, with the back edge 2 -> 1
        g = networkx.DiGraph([(0, 1), (1, 2), (2, 1), (2, 3)])
        version = [0]
        helper = DirectedGraphHelper(g, True, 0, graph_version=lambda: version[0])
        assert helper.loop_heads() == {1}

        g.remove_edge(2, 1)
        version[0] += 1
        assert helper.loop_heads() == set()
        order = helper.get_node_order()
        assert order[1] < order[2] < order[3]

    def test_node_order_is_kept_across_merges(self):
        g = networkx.DiGraph([(0, 1), (1, 2), (2, 1), (2, 3)])
        version = [0]
        helper = DirectedGraphHelper(g, True, 0, graph_version=lambda: version[0])
        helper.get_node_order()
        was_current = helper.node_order_is_current()
        assert was_current

        # merge 3 into 2, mirrored the way replace_nodes_both does it
        g.remove_node(3)
        version[0] += 1
        helper.replace_nodes(2, 3, 2)
        helper.resync_node_order(was_current)
        assert helper.node_order_is_current()
        assert helper.loop_heads() == {1}


if __name__ == "__main__":
    main()
