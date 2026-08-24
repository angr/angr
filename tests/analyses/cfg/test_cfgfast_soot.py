#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.knowledge_plugins.cfg.spilling_cfg import SpillingCFG, get_block_key

try:
    import pysoot
except ModuleNotFoundError:
    pysoot = None

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
@unittest.skipUnless(pysoot, "pysoot not available")
class TestCfgfastSoot(unittest.TestCase):
    def test_simple1(self):
        binary_path = os.path.join(test_location, "java", "simple1.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple1.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()

    def test_simple2(self):
        binary_path = os.path.join(test_location, "java", "simple2.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple2.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()

    def test_soot_cfg_declines_to_spill(self):
        """A Soot CFG must never spill: CFGNode, edge, and Function values are all serialized with encoders that
        only understand integer addresses, so evicting one raises TypeError/struct.error instead of writing a
        record. The spilling layer therefore keeps a Soot CFG entirely in memory."""
        binary_path = os.path.join(test_location, "java", "simple1.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple1.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()

        graph = cfg.model.graph
        assert graph.addr_type == "soot"

        # A cache limit small enough to force eviction must be declined rather than crash while serializing.
        total_nodes = len(graph)
        assert total_nodes > 2
        graph.cache_limit = 1
        graph.db_batch_size = 1
        assert graph.spilled_count == 0
        assert len(graph) == total_nodes

        total_functions = len(p.kb.functions)
        assert total_functions > 1
        p.kb.functions.cache_limit = 1
        assert len(p.kb.functions) == total_functions

        assert graph.cache_limit is None
        assert p.kb.functions.cache_limit is None
        assert not p.kb.functions.spillable

    def test_soot_graph_survives_a_cache_limit_smaller_than_the_graph(self):
        """A Soot-typed graph built with a cache limit far below its size must still hold every node and edge, with
        their attributes intact: the spilling encoders cannot serialize Soot addresses, so nothing may be evicted."""
        binary_path = os.path.join(test_location, "java", "simple1.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple1.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()

        nodes = list(cfg.model.graph.nodes())
        edges = [(src, dst, cfg.model.graph.get_edge_data(src, dst)) for src, dst in cfg.model.graph.edges]
        assert len(nodes) > 4
        assert len(edges) > 4

        # A limit of 2 with a batch size of 1 means eviction is attempted long before the last node is inserted.
        graph = SpillingCFG(
            rtdb=p.kb.rtdb,
            cache_limit=2,
            db_batch_size=1,
            edge_cache_limit=2,
            edge_db_batch_size=1,
            addr_type="soot",
        )
        for node in nodes:
            graph.add_node(node)
        for src, dst, data in edges:
            graph.add_edge(src, dst, **data)

        assert len(graph) == len(nodes)
        assert graph.number_of_edges() == len(edges)
        for node in nodes:
            assert node in graph
            assert graph.get_node_by_key(get_block_key(node)).addr == node.addr
        for src, dst, data in edges:
            assert graph.has_edge(src, dst)
            assert graph.get_edge_data(src, dst) == data


if __name__ == "__main__":
    unittest.main()
