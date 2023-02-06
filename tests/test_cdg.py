import os
import unittest

import networkx

import angr
from angr.analyses.cdg import TemporaryNode
from angr.utils.graph import compute_dominance_frontier

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCdg(unittest.TestCase):
    def test_graph_0(self):
        # This graph comes from Fig.1 of paper An Efficient Method of Computing Static Single Assignment Form by Ron
        # Cytron, etc.

        # Create a project with a random binary - it will not be used anyways
        p = angr.Project(
            os.path.join(test_location, "x86_64", "datadep_test"),
            load_options={"auto_load_libs": False},
            use_sim_procedures=True,
        )

        # Create the CDG analysis
        cfg = p.analyses.CFGEmulated(no_construct=True)

        # Create our mock control flow graph
        g = networkx.DiGraph()
        edges = [
            ("Entry", 1),
            (1, 2),
            (2, 3),
            (2, 7),
            (3, 4),
            (3, 5),
            (4, 6),
            (5, 6),
            (6, 8),
            (7, 8),
            (8, 9),
            (9, 10),
            (9, 11),
            (11, 9),
            (10, 11),
            (11, 12),
            (12, 2),
            (12, "Exit"),
            ("Entry", "Exit"),
        ]

        for src, dst in edges:
            # Create a TemporaryNode for each node
            n1 = TemporaryNode(src)
            n2 = TemporaryNode(dst)
            g.add_edge(n1, n2)

        # Manually set the CFG
        cfg.model.graph = g
        cfg.model._nodes = {}
        cfg._edge_map = {}
        cfg._loop_back_edges = []
        cfg._overlapped_loop_headers = []

        # Call _construct()
        cdg = p.analyses.CDG(cfg=cfg, no_construct=True)
        cdg._entry = TemporaryNode("Entry")
        cdg._construct()

        standard_result = {
            "Entry": {1, 2, 8, 9, 11, 12},
            1: set(),
            2: {3, 6, 7},
            3: {4, 5},
            4: set(),
            5: set(),
            6: set(),
            7: set(),
            8: set(),
            9: {10},
            10: set(),
            11: {9, 11},
            12: {2, 8, 9, 11, 12},
        }

        for node, cd_nodes in standard_result.items():
            # Each node in set `cd_nodes` is control dependent on `node`
            for n in cd_nodes:
                assert cdg.graph.has_edge(TemporaryNode(node), TemporaryNode(n))
            assert len(cdg.graph.out_edges(TemporaryNode(node))) == len(cd_nodes)

    def test_dominance_frontiers(self):
        # This graph comes from Fig.1 of paper An Efficient Method of Computing Static Single Assignment Form by Ron
        # Cytron, etc.

        # Create our mock control flow graph
        g = networkx.DiGraph()
        g.add_edge("Entry", 1)
        g.add_edge(1, 2)
        g.add_edge(2, 3)
        g.add_edge(2, 7)
        g.add_edge(3, 4)
        g.add_edge(3, 5)
        g.add_edge(4, 6)
        g.add_edge(5, 6)
        g.add_edge(6, 8)
        g.add_edge(7, 8)
        g.add_edge(8, 9)
        g.add_edge(9, 10)
        g.add_edge(9, 11)
        g.add_edge(11, 9)
        g.add_edge(10, 11)
        g.add_edge(11, 12)
        g.add_edge(12, 2)
        g.add_edge(12, "Exit")
        g.add_edge("Entry", "Exit")

        # Create the mock post-dom graph
        postdom = networkx.DiGraph()
        postdom.add_edge("Entry", 1)
        postdom.add_edge(1, 2)
        postdom.add_edge(2, 3)
        postdom.add_edge(3, 4)
        postdom.add_edge(3, 5)
        postdom.add_edge(3, 6)
        postdom.add_edge(2, 7)
        postdom.add_edge(2, 8)
        postdom.add_edge(8, 9)
        postdom.add_edge(9, 10)
        postdom.add_edge(9, 11)
        postdom.add_edge(11, 12)
        postdom.add_edge("Entry", "Exit")

        # Call df_construct()
        df = compute_dominance_frontier(g, postdom)

        standard_df = {
            1: {"Exit"},
            2: {"Exit", 2},
            3: {8},
            4: {6},
            5: {6},
            6: {8},
            7: {8},
            8: {"Exit", 2},
            9: {"Exit", 2, 9},
            10: {11},
            11: {"Exit", 2, 9},
            12: {"Exit", 2},
            "Entry": set(),
            "Exit": set(),
        }
        assert df == standard_df


if __name__ == "__main__":
    unittest.main()
