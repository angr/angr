#!/usr/bin/env python3
# pylint:disable=no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import os
import pickle
import tempfile
import unittest
from unittest import mock

import networkx

import angr
from angr.angrdb import AngrDB
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_model import CFGModel
from angr.knowledge_plugins.cfg.cfg_node import CFGENode, CFGNode
from angr.knowledge_plugins.cfg.spilling_cfg import SpillingCFG, get_block_key
from angr.rustylib.cfg_graph import PRESENT_INS_ADDR, PRESENT_JUMPKIND, PRESENT_STMT_IDX, CfgGraph
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCfgGraph(unittest.TestCase):
    """The packed Rust store."""

    def test_nodes_edges_degrees(self):
        g = CfgGraph()
        a, created = g.add_node(0x1000, 8)
        assert created
        assert g.add_node(0x1000, 8) == (a, False)
        b, _ = g.add_node(0x1008, 4)
        c, _ = g.add_node(0x1008, 6)
        assert g.nodes_at_addr(0x1008) == [b, c]
        assert g.find_node(0x1008, 6) == c
        assert g.find_node(0x1008, 7) is None

        assert g.add_edge(a, b, PRESENT_JUMPKIND | PRESENT_INS_ADDR | PRESENT_STMT_IDX, "Ijk_Boring", 0x1004, 3)
        assert not g.add_edge(a, b, PRESENT_JUMPKIND, "Ijk_Call")
        assert g.edge_data(a, b) == {"jumpkind": "Ijk_Call", "ins_addr": 0x1004, "stmt_idx": 3}
        assert g.add_edge(a, c, PRESENT_JUMPKIND, None)
        assert g.edge_data(a, c) == {"jumpkind": None}
        assert g.edge_data(b, a) is None
        assert g.out_degree(a) == 2 and g.in_degree(b) == 1 and g.in_degree(a) == 0
        assert g.successors(a) == [b, c] and g.predecessors(c) == [a]
        assert g.edges() == [(a, b), (a, c)]
        assert g.number_of_nodes() == 3 and g.number_of_edges() == 2
        assert g.remove_edge(a, c) and not g.remove_edge(a, c)
        with self.assertRaises(KeyError):
            g.add_edge(a, 99, 0)

    def test_remove_node_and_reinsert_order(self):
        g = CfgGraph()
        a, _ = g.add_node(1, 1)
        b, _ = g.add_node(2, 1)
        c, _ = g.add_node(3, 1)
        g.add_edge(a, b, PRESENT_JUMPKIND, "Ijk_Boring")
        g.add_edge(b, c, PRESENT_JUMPKIND, "Ijk_Boring")
        assert g.remove_node(b) and not g.remove_node(b)
        assert g.number_of_edges() == 0 and g.out_degree(a) == 0
        assert not g.has_addr(2) and g.find_node(2, 1) is None
        b2, _ = g.add_node(2, 1)
        assert b2 != b
        assert g.nodes() == [a, c, b2]
        assert g.node_keys() == [(1, 1), (3, 1), (2, 1)]

    def test_call_destinations(self):
        g = CfgGraph()
        a, _ = g.add_node(1, 1)
        b, _ = g.add_node(2, 1)
        c, _ = g.add_node(3, 1)
        g.add_edge(a, b, PRESENT_JUMPKIND, "Ijk_Call")
        g.add_edge(c, b, PRESENT_JUMPKIND, "Ijk_Sys_syscall")
        g.add_edge(a, c, PRESENT_JUMPKIND, "Ijk_Boring")
        assert g.call_destinations() == [b]
        g.remove_edge(a, b)
        assert g.is_call_destination(b)
        g.remove_node(c)
        assert g.call_destinations() == []

    def test_pickle_keeps_ids(self):
        g = CfgGraph()
        a, _ = g.add_node(1, 1)
        b, _ = g.add_node(2, -1)
        c, _ = g.add_node(3, 1)
        g.add_edge(a, c, PRESENT_JUMPKIND | PRESENT_STMT_IDX, "Ijk_FakeRet", None, -2)
        g.remove_node(b)
        g2 = pickle.loads(pickle.dumps(g))
        assert g2.nodes() == [a, c]
        assert g2.edges_with_data() == [(a, c, {"jumpkind": "Ijk_FakeRet", "stmt_idx": -2})]
        assert g2.add_node(2, -1)[0] == 3


def _node(addr, size=4, name=None):
    return CFGNode(addr, size, None, block_id=addr, name=name)


class TestSpillingCFG(unittest.TestCase):
    """The SpillingCFG wrapper on top of CfgGraph."""

    def test_crud_and_views(self):
        g = SpillingCFG()
        n1, n2, n3 = _node(0x1000), _node(0x1004), _node(0x1008)
        g.add_node(n1)
        g.add_edge(n1, n2, jumpkind="Ijk_Boring", ins_addr=0x1000, stmt_idx=1)
        g.add_edge(n2, n3, jumpkind="Ijk_Call", ins_addr=0x1004, stmt_idx=None)
        assert len(g) == 3 and g.number_of_edges() == 2
        assert n1 in g and _node(0x2000) not in g
        assert g.has_edge(n1, n2) and not g.has_edge(n2, n1)
        assert g[n1][n2] == {"jumpkind": "Ijk_Boring", "ins_addr": 0x1000, "stmt_idx": 1}
        assert n2 in g[n1] and n3 not in g[n1]
        assert list(g.successors(n1)) == [n2] and list(g.predecessors(n3)) == [n2]
        assert g.out_degree(n2) == 1 and g.in_degree(n1) == 0 and g.in_degree[n3] == 1
        assert g.out_degree_by_key(get_block_key(n1)) == 1
        assert [(s.addr, d.addr) for s, d in g.edges()] == [(0x1000, 0x1004), (0x1004, 0x1008)]
        assert [(s.addr, d.addr, data["jumpkind"]) for s, d, data in g.in_edges(n3, data=True)] == [
            (0x1004, 0x1008, "Ijk_Call")
        ]
        assert [(s.addr, d.addr) for s, d in g.out_edges([n1, n2])] == [(0x1000, 0x1004), (0x1004, 0x1008)]
        assert list(g.out_edges_by_key(get_block_key(n1))) == [(get_block_key(n1), get_block_key(n2))]
        assert g.call_destination_keys == {get_block_key(n3)}
        assert list(g.nodes_by_addr(0x1004)) == [n2] and g.has_node_addr(0x1004)
        assert sorted(g.node_addrs()) == [0x1000, 0x1004, 0x1008]

        g.remove_edge(n1, n2)
        with self.assertRaises(networkx.NetworkXError):
            g.remove_edge(n1, n2)
        g.remove_node(n2)
        assert n2 not in g and not g.has_node_addr(0x1004) and g.number_of_edges() == 0
        assert g.call_destination_keys == set()
        assert g.get_edge_data(n1, n3, default="x") == "x"

        nx = g.to_networkx()
        assert set(nx.nodes()) == {n1, n3}
        g.from_networkx(nx)
        assert len(g) == 2

    def test_add_edge_merges_attributes(self):
        g = SpillingCFG()
        n1, n2 = _node(0x1000), _node(0x1004)
        g.add_edge(n1, n2, jumpkind="Ijk_Boring")
        assert g.get_edge_data(n1, n2) == {"jumpkind": "Ijk_Boring"}
        g.add_edge(n1, n2, ins_addr=0x1002)
        assert g.get_edge_data(n1, n2) == {"jumpkind": "Ijk_Boring", "ins_addr": 0x1002}
        assert g.number_of_edges() == 1

    def test_extra_edge_attributes(self):
        g = SpillingCFG()
        n1, n2 = _node(0x1000), _node(0x1004)
        g.add_edge(n1, n2, jumpkind="Ijk_Ret", stmt_id=-2, ins_addr=(1, 2))
        assert g.get_edge_data(n1, n2) == {"jumpkind": "Ijk_Ret", "stmt_id": -2, "ins_addr": (1, 2)}
        assert next(iter(g.edges(data=True)))[2]["stmt_id"] == -2
        g2 = pickle.loads(pickle.dumps(g))
        assert next(iter(g2.edges(data=True)))[2] == {"jumpkind": "Ijk_Ret", "stmt_id": -2, "ins_addr": (1, 2)}
        g2.remove_node(n2)
        assert not g2._extra_edge_attrs

    def test_pickle_and_copy(self):
        g = SpillingCFG()
        n1, n2, n3 = _node(0x1000), _node(0x1004), _node(0x1008)
        g.add_edge(n1, n2, jumpkind="Ijk_Boring", ins_addr=0x1000, stmt_idx=1)
        g.add_edge(n2, n3, jumpkind="Ijk_Call", ins_addr=0x1004, stmt_idx=None)
        g.remove_node(n3)
        g.add_node(n3)
        for g2 in (pickle.loads(pickle.dumps(g)), g.copy()):
            assert [n.addr for n in g2.nodes()] == [0x1000, 0x1004, 0x1008]
            assert [(s.addr, d.addr, d_) for s, d, d_ in g2.edges(data=True)] == [
                (0x1000, 0x1004, {"jumpkind": "Ijk_Boring", "ins_addr": 0x1000, "stmt_idx": 1})
            ]
            g2.add_edge(n2, n3, jumpkind="Ijk_Call")
            assert g2.call_destination_keys == {get_block_key(n3)}
        assert g.number_of_edges() == 1

    def test_block_id_keys(self):
        g = SpillingCFG(addr_type="block_id")
        nodes = [
            CFGENode(
                0x1000, 4, None, callstack_key=(None, None), looping_times=lt, block_id=BlockID(0x1000, None, "normal")
            )
            for lt in (0, 1)
        ]
        other = CFGENode(0x2000, 4, None, callstack_key=(None, None), block_id=BlockID(0x2000, (0x1000,), "normal"))
        g.add_edge(nodes[0], nodes[1], jumpkind="Ijk_Boring", ins_addr=0x1000, stmt_idx=0)
        g.add_edge(nodes[1], other, jumpkind="Ijk_Call", ins_addr=0x1000, stmt_idx=0)
        assert len(g) == 3 and len(list(g.nodes_by_addr(0x1000))) == 2
        assert list(g.successors(nodes[0])) == [nodes[1]]
        assert g.call_destination_keys == {get_block_key(other)}
        g.remove_node(nodes[0])
        assert len(list(g.nodes_by_addr(0x1000))) == 1
        g2 = pickle.loads(pickle.dumps(g))
        assert [(s.addr, d.addr) for s, d in g2.edges()] == [(0x1000, 0x2000)]
        assert list(g2.predecessors(other)) == [nodes[1]]
        g2.add_node(nodes[0])
        assert len(g2) == 3 and g2.call_destination_keys == {get_block_key(other)}

    def test_cfgmodel_angrdb_round_trip_spilled(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        model = cfg.model

        def edge_recs(m: CFGModel):
            return sorted(
                (s.addr, s.size, d.addr, d.size, data["jumpkind"], data.get("ins_addr"), data.get("stmt_idx"))
                for s, d, data in m.graph.edges(data=True)
            )

        expected = edge_recs(model)
        assert expected and model.graph.call_destination_keys

        # protobuf round trip (what angrdb stores), on the materialised path and on the spilled fast path
        cmsg = model.serialize_to_cmessage()
        back = CFGModel.parse_from_cmessage(cmsg)
        assert edge_recs(back) == expected
        assert back.graph.call_destination_keys == model.graph.call_destination_keys

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "fauxware.adb")
            AngrDB(proj, nullpool=True).dump(db_file)
            with mock.patch.object(angr.Project, "get_cfg_node_cache_limit", return_value=5):
                loaded = AngrDB(nullpool=True).load(db_file)
        loaded_model = loaded.kb.cfgs["CFGFast"]
        assert loaded_model.graph.spilled_count > 0
        assert edge_recs(loaded_model) == expected
        assert loaded_model.graph.call_destination_keys == model.graph.call_destination_keys

        # pickle round trip of the model
        pickled = pickle.loads(pickle.dumps(model))
        assert edge_recs(pickled) == expected
        assert {n.addr for n in pickled.graph.nodes()} == {n.addr for n in model.graph.nodes()}


if __name__ == "__main__":
    unittest.main()
