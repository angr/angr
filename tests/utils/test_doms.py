# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
from unittest import main, TestCase

import networkx

from angr.utils.doms import IncrementalDominators


class TestDoms(TestCase):
    def test_simple_doms(self):

        g = networkx.DiGraph()
        g.add_edges_from(
            [
                (1, 2),
                (1, 3),
                (3, 4),
                (4, 5),
                (2, 5),
                (5, 6),
                (6, 7),
            ]
        )

        doms = IncrementalDominators(g, 1)
        assert doms.idom(1) == 1
        assert doms.idom(2) == 1
        assert doms.idom(3) == 1
        assert doms.idom(4) == 3
        assert doms.idom(5) == 1
        assert doms.idom(6) == 5
        assert doms.idom(7) == 6

    def test_simple_postdoms(self):

        g = networkx.DiGraph()
        g.add_edges_from(
            [
                (1, 2),
                (1, 3),
                (3, 4),
                (4, 5),
                (2, 5),
                (5, 6),
                (6, 7),
            ]
        )

        postdoms = IncrementalDominators(g, 7, post=True)
        assert postdoms.idom(7) == 7
        assert postdoms.idom(6) == 7
        assert postdoms.idom(5) == 6
        assert postdoms.idom(2) == 5
        assert postdoms.idom(4) == 5
        assert postdoms.idom(3) == 4
        assert postdoms.idom(1) == 5

    def test_doms_on_changed_graphs(self):
        g = networkx.DiGraph()
        g.add_edges_from(
            [
                # if
                (1, 2),
                (1, 3),
                (2, 3),
                # if
                (3, 4),
                (3, 5),
                (4, 5),
                # if
                (5, 6),
                (5, 7),
                (6, 7),
                # a switch-case
                (7, 8),
                (7, 9),
                (7, 10),
                (7, 11),
                (7, 12),
                (8, 13),
                (9, 13),
                (10, 13),
                (11, 13),
                (12, 13),
            ]
        )

        doms = IncrementalDominators(g, 1)
        assert doms.idom(13) == 7
        assert doms.idom(5) == 3

        # getting rid of the switch-case
        g.remove_nodes_from([7, 8, 9, 10, 11, 12])
        g.add_edges_from([(5, 13), (6, 13)])
        doms.graph_updated(5, {7, 8, 9, 10, 11, 12}, 7)
        assert doms.idom(13) == 5

    def test_nonexistent_nodes(self):
        g = networkx.DiGraph()
        g.add_edges_from(
            [
                (1, 2),
                (1, 3),
                (2, 3),
            ]
        )
        g.add_node(4)

        doms = IncrementalDominators(g, 1)
        assert doms.idom(3) == 1
        assert doms.idom(4) is None
        assert doms.idom(5) is None

    def test_cycles(self):
        g = networkx.DiGraph()
        g.add_edges_from(
            [
                (1, 2),
                (1, 3),
                (3, 4),
                (4, 5),
                (2, 5),
                (5, 2),
            ]
        )

        doms = IncrementalDominators(g, 1)
        assert doms.idom(1) == 1
        assert doms.idom(2) == 1
        assert doms.idom(3) == 1
        assert doms.idom(4) == 3
        assert doms.idom(5) == 1


if __name__ == "__main__":
    main()
