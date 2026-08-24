#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor

import angr
from angr.knowledge_plugins.cfg import CFGModel
from angr.knowledge_plugins.cfg.spilling_cfg import SpillingCFG, get_block_key
from angr.knowledge_plugins.functions import Function

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

    @staticmethod
    def _simple1_cfg():
        binary_path = os.path.join(test_location, "java", "simple1.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple1.Class1.main"}, auto_load_libs=False)
        return p, p.analyses.CFGFastSoot()

    def test_soot_cfg_model_round_trips_through_a_cmessage(self):
        _, cfg = self._simple1_cfg()
        assert cfg.model.addr_type == "soot"

        model = CFGModel.parse_from_cmessage(cfg.model.serialize_to_cmessage())

        def nodes_of(m):
            return sorted((n.addr, n.size, n.function_address) for n in m.graph.nodes())

        def edges_of(m):
            return sorted(
                (src.addr, dst.addr, data.get("jumpkind"), data.get("ins_addr"), data.get("stmt_idx"))
                for src, dst, data in m.graph.edges(data=True)
            )

        assert nodes_of(model) == nodes_of(cfg.model)
        assert edges_of(model) == edges_of(cfg.model)
        for node in model.graph.nodes():
            assert isinstance(node.addr, SootAddressDescriptor)
            assert isinstance(node.function_address, SootMethodDescriptor)

    def test_soot_function_round_trips_through_a_cmessage(self):
        p, _ = self._simple1_cfg()
        assert p.kb.functions

        for func in list(p.kb.functions.values()):
            parsed = Function.parse_from_cmessage(
                func.serialize_to_cmessage(), function_manager=p.kb.functions, project=p
            )
            assert parsed.addr == func.addr
            assert isinstance(parsed.addr, SootMethodDescriptor)
            assert {n.addr for n in parsed.transition_graph} == {n.addr for n in func.transition_graph}
            assert sorted(parsed.get_call_sites()) == sorted(func.get_call_sites())
            for call_site in func.get_call_sites():
                assert parsed.get_call_target(call_site) == func.get_call_target(call_site)
                assert parsed.get_call_return(call_site) == func.get_call_return(call_site)

    def test_soot_cfg_survives_node_and_edge_eviction(self):
        p, cfg = self._simple1_cfg()
        nodes = list(cfg.model.graph.nodes())
        edges = [(src, dst, cfg.model.graph.get_edge_data(src, dst)) for src, dst in cfg.model.graph.edges]
        assert len(nodes) > 4
        assert len(edges) > 4

        # a limit of 2 with a batch size of 1 evicts long before the last node is inserted
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

        assert graph.spilled_count > 0
        assert len(graph) == len(nodes)
        assert graph.number_of_edges() == len(edges)
        for node in nodes:
            reloaded = graph.get_node_by_key(get_block_key(node))
            assert reloaded.addr == node.addr
            assert reloaded.size == node.size
            assert reloaded.function_address == node.function_address
        for src, dst, data in edges:
            assert graph.get_edge_data(src, dst) == data

    def test_soot_functions_survive_eviction(self):
        p, _ = self._simple1_cfg()
        before = {addr: {n.addr for n in func.transition_graph} for addr, func in p.kb.functions.items()}
        assert len(before) > 1

        p.kb.functions.cache_limit = 1
        assert p.kb.functions.cached_function_count <= 1

        for addr, node_addrs in before.items():
            func = p.kb.functions[addr]
            assert func.addr == addr
            assert isinstance(func.addr, SootMethodDescriptor)
            assert {n.addr for n in func.transition_graph} == node_addrs

    def test_simple2_without_entry_point(self):
        # simple2.jar has no Main-Class manifest attribute, so without an explicit entry_point the loader leaves
        # Project.entry at 0. CFGFastSoot must still analyze every method of every class.
        binary_path = os.path.join(test_location, "java", "simple2.jar")
        p = angr.Project(binary_path, auto_load_libs=False)
        assert p.entry == 0
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()
        function_names = {f.name for f in p.kb.functions.values()}
        assert "simple2.Class1.main(java.lang.String[])" in function_names
        # methods that no entry point reaches are analyzed too
        assert "simple2.Class1.unreachable(int)" in function_names

    def test_invokespecial_on_an_interface(self):
        # Impl.greet() calls Greeter.super.greet(), so the invoke's declaring class is an interface.
        # Resolving it asks SootClassHierarchy whether that interface is a subclass of Impl;
        # get_super_classes has no chain to walk for an interface and raises, which aborted the CFG.
        binary_path = os.path.join(test_location, "java", "interface_default.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "iface.Impl.main"}, auto_load_libs=False)

        cfg = p.analyses.CFGFastSoot()

        assert cfg.graph.nodes()
        names = {f.name for f in cfg.kb.functions.values()}
        assert any("greet" in name for name in names), names


if __name__ == "__main__":
    unittest.main()
