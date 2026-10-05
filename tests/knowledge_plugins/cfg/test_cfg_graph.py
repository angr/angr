#!/usr/bin/env python3
# pylint:disable=no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import os
import pickle
import tempfile
import threading
import time
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
        b2, created = g.add_node(2, 1)
        assert created
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
        assert g2.add_node(2, -1)[1]
        assert g2.node_keys() == [(1, 1), (3, 1), (2, -1)]


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


class _DictBackend:
    """A SegmentBackend over a dict (what the RuntimeDb-backed CFGSegmentStore does with LMDB)."""

    def __init__(self):
        self.blobs: dict[int, bytes] = {}
        self.puts = 0

    def get(self, window):
        return self.blobs.get(window)

    def put(self, window, data):
        self.blobs[window] = bytes(data)
        self.puts += 1

    def delete(self, window):
        self.blobs.pop(window, None)

    def delete_all(self):
        self.blobs.clear()


def _edge_recs(m: CFGModel):
    return sorted(
        (s.addr, s.size, d.addr, d.size, data["jumpkind"], data.get("ins_addr"), data.get("stmt_idx"))
        for s, d, data in m.graph.edges(data=True)
    )


def _node_recs(m: CFGModel):
    return sorted((n.addr, n.size, n.function_address) for n in m.graph.nodes())


class TestPagedCfgGraph(unittest.TestCase):
    """Segmented layout, cross-segment edges, paging backends, promotion and round trips."""

    @staticmethod
    def _populate(g: CfgGraph) -> dict[int, int]:
        # window_shift=4: 16-byte windows; the node at 0xc straddles the 0x10 boundary
        ids = {}
        for addr, size in [(0xC, 8), (0x14, 4), (0x18, 4), (0x2, 2), (0x30, 2)]:
            ids[addr] = g.add_node(addr, size)[0]
        g.add_edge(ids[0xC], ids[0x14], PRESENT_JUMPKIND | PRESENT_INS_ADDR | PRESENT_STMT_IDX, "Ijk_Call", 0x10, 1)
        g.add_edge(ids[0x14], ids[0x18], PRESENT_JUMPKIND, "Ijk_Boring")
        g.add_edge(ids[0x18], ids[0xC], PRESENT_JUMPKIND, "Ijk_Ret")
        g.add_edge(ids[0x18], ids[0x2], PRESENT_JUMPKIND, "Ijk_Boring")
        g.add_edge(ids[0xC], ids[0xC], PRESENT_JUMPKIND, "Ijk_Boring")
        g.add_edge(ids[0x30], ids[0x14], PRESENT_JUMPKIND, "Ijk_Call")
        return ids

    @staticmethod
    def _snapshot(g: CfgGraph):
        key = g.node_key
        return (
            g.node_keys(),
            [(key(s), key(d), data) for s, d, data in g.edges_with_data()],
            [key(i) for i in g.call_destinations()],
            {key(i): ([key(x) for x in g.successors(i)], [key(x) for x in g.predecessors(i)]) for i in g.nodes()},
        )

    def test_window_boundary_and_cross_segment_edges(self):
        g = CfgGraph(window_shift=4)
        ids = self._populate(g)
        assert g.stats()["segments"] == 3
        assert (ids[0xC] >> 32) != (ids[0x14] >> 32)
        assert g.find_node(0xC, 8) == ids[0xC] and g.nodes_at_addr(0xC) == [ids[0xC]]
        assert sorted(g.addrs()) == [0x2, 0xC, 0x14, 0x18, 0x30]
        assert g.successors(ids[0xC]) == [ids[0x14], ids[0xC]]
        assert g.predecessors(ids[0x14]) == [ids[0xC], ids[0x30]]
        assert g.in_degree(ids[0x14]) == 2 and g.out_degree(ids[0x18]) == 2
        assert g.has_edge(ids[0xC], ids[0x14]) and not g.has_edge(ids[0x14], ids[0xC])
        assert g.edge_data(ids[0xC], ids[0x14]) == {"jumpkind": "Ijk_Call", "ins_addr": 0x10, "stmt_idx": 1}
        assert g.edge_tuple(ids[0x14], ids[0x18]) == ("Ijk_Boring", None, None)
        assert g.out_edges_jumpkinds(ids[0x18]) == [(ids[0xC], "Ijk_Ret"), (ids[0x2], "Ijk_Boring")]
        # merge through the mirror: both segments see the merged record
        g.add_edge(ids[0xC], ids[0x14], PRESENT_STMT_IDX, None, None, 5)
        assert g.in_edges_with_data(ids[0x14])[0][2] == {"jumpkind": "Ijk_Call", "ins_addr": 0x10, "stmt_idx": 5}
        assert g.call_destinations() == [ids[0x14]]
        # removing the cross-segment call edge re-checks the sticky flag and drops the mirror
        assert g.remove_edge(ids[0xC], ids[0x14])
        assert g.is_call_destination(ids[0x14])
        assert g.remove_edge(ids[0x30], ids[0x14])
        assert not g.is_call_destination(ids[0x14]) and g.predecessors(ids[0x14]) == []
        assert g.number_of_edges() == 4
        # removing a node with cross-segment in- and out-edges
        assert g.remove_node(ids[0x18])
        assert g.successors(ids[0x14]) == [] and g.predecessors(ids[0x2]) == []
        assert g.predecessors(ids[0xC]) == [ids[0xC]]
        assert g.number_of_edges() == 1 and g.number_of_nodes() == 4
        assert g.nodes() == [ids[0xC], ids[0x14], ids[0x2], ids[0x30]]
        with self.assertRaises(KeyError):
            g.successors(ids[0x18])

    def test_memory_backend_eviction_writeback_reload(self):
        ref = CfgGraph(window_shift=4)
        self._populate(ref)
        g = CfgGraph(window_shift=4)
        g.attach_memory_backend(1)  # nothing fits: every operation evicts and reloads
        ids = self._populate(g)
        st = g.stats()
        assert st["paged"] and st["evictions"] > 0 and st["loads"] > 0 and st["writebacks"] > 0
        assert st["resident_segments"] <= 1
        assert self._snapshot(g) == self._snapshot(ref)
        g.remove_node(ids[0x18])
        ref.remove_node(ref.find_node(0x18, 4))
        assert self._snapshot(g) == self._snapshot(ref)
        g.detach_backend()
        assert not g.paged and g.stats()["resident_segments"] == g.stats()["segments"]
        assert self._snapshot(g) == self._snapshot(ref)

    def test_python_backend_and_pickle(self):
        ref = CfgGraph(window_shift=4)
        self._populate(ref)
        backend = _DictBackend()
        g = CfgGraph(window_shift=4)
        g.attach_backend(backend, 1)
        self._populate(g)
        assert g.paged and backend.puts > 0 and backend.blobs
        assert self._snapshot(g) == self._snapshot(ref)
        g.budget_bytes = 1 << 20
        for i in g.nodes():
            g.node_key(i)
        assert g.stats()["resident_segments"] == g.stats()["segments"]
        g.flush()
        assert len(backend.blobs) == g.stats()["segments"]
        # pickling a paged graph takes the blobs from the backend; the copy is resident
        g2 = pickle.loads(pickle.dumps(g))
        assert not g2.paged and self._snapshot(g2) == self._snapshot(ref)
        assert self._snapshot(g.copy()) == self._snapshot(ref)
        g.clear()
        assert not backend.blobs and g.number_of_nodes() == 0

    def test_concurrent_reader_during_backend_call(self):
        # py-lmdb releases the GIL inside put/get; a reader on another thread must wait, not raise

        class SlowBackend(_DictBackend):
            def put(self, window, data):
                time.sleep(0.0005)
                super().put(window, data)

            def get(self, window):
                time.sleep(0.0005)
                return super().get(window)

        g = CfgGraph(window_shift=4)
        g.attach_backend(SlowBackend(), 1)
        errors = []
        stop = threading.Event()

        def reader():
            try:
                while not stop.is_set():
                    g.stats()
                    g.number_of_nodes()
            except Exception as ex:  # pylint:disable=broad-exception-caught
                errors.append(ex)

        t = threading.Thread(target=reader)
        t.start()
        try:
            for _ in range(20):
                ids = self._populate(g)
                g.remove_node(ids[0x18])
                g.clear()
        finally:
            stop.set()
            t.join()
        assert not errors, errors[:1]

    def test_block_id_keys_survive_id_reuse(self):
        g = SpillingCFG(addr_type="block_id")
        nodes = [
            CFGENode(
                0x1000 + i * 4, 4, None, callstack_key=(None, None), block_id=BlockID(0x1000 + i * 4, None, "normal")
            )
            for i in range(3)
        ]
        g.add_edge(nodes[0], nodes[1], jumpkind="Ijk_Boring")
        g.add_edge(nodes[1], nodes[2], jumpkind="Ijk_Call")
        g.remove_node(nodes[1])
        g.add_node(nodes[1])
        g.add_edge(nodes[2], nodes[1], jumpkind="Ijk_Boring")
        assert [n.addr for n in g.nodes()] == [0x1000, 0x1008, 0x1004]
        assert [(s.addr, d.addr) for s, d in g.edges()] == [(0x1008, 0x1004)]
        g2 = pickle.loads(pickle.dumps(g))
        assert [(s.addr, d.addr) for s, d in g2.edges()] == [(0x1008, 0x1004)]
        assert list(g2.predecessors(nodes[1])) == [nodes[2]] and g2.call_destination_keys == set()

    def test_cfgfast_paged_matches_resident(self):
        binary = os.path.join(test_location, "x86_64", "fauxware")
        ref_proj = angr.Project(binary, auto_load_libs=False)
        ref = ref_proj.analyses.CFGFast(normalize=True).model
        assert not ref.graph.paged
        # an explicit budget pages the graph from the start; nothing fits in one byte
        proj = angr.Project(binary, auto_load_libs=False, cache_limits={"cfg_segment_bytes": 1})
        model = proj.analyses.CFGFast(normalize=True).model
        stats = model.graph.segment_stats()
        assert model.graph.paged and stats["loads"] > 0 and stats["evictions"] > 0
        assert _node_recs(model) == _node_recs(ref) and _edge_recs(model) == _edge_recs(ref)
        assert {f.addr: sorted(f.block_addrs_set) for f in proj.kb.functions.values()} == {
            f.addr: sorted(f.block_addrs_set) for f in ref_proj.kb.functions.values()
        }
        assert model.graph.call_destination_keys == ref.graph.call_destination_keys

        # protobuf: segment blobs instead of edges
        cmsg = model.serialize_to_cmessage()
        assert cmsg.graph_segments and not cmsg.edges
        back = CFGModel.parse_from_cmessage(cmsg)
        assert _edge_recs(back) == _edge_recs(ref) and not back.graph.paged

        # angrdb round trip, loaded resident and loaded paged (spilled node fast path)
        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "fauxware.adb")
            AngrDB(proj, nullpool=True).dump(db_file)
            loaded = AngrDB(nullpool=True).load(db_file)
            assert _edge_recs(loaded.kb.cfgs["CFGFast"]) == _edge_recs(ref)
            with (
                mock.patch.object(angr.Project, "get_cfg_node_cache_limit", return_value=5),
                mock.patch.object(angr.Project, "get_cfg_segment_budget", return_value=1),
            ):
                loaded = AngrDB(nullpool=True).load(db_file)
            lm = loaded.kb.cfgs["CFGFast"]
            assert lm.graph.paged and lm.graph.spilled_count > 0
            assert _edge_recs(lm) == _edge_recs(ref) and _node_recs(lm) == _node_recs(ref)

        # pickle round trip of the paged model
        pickled = pickle.loads(pickle.dumps(model))
        assert _edge_recs(pickled) == _edge_recs(ref) and _node_recs(pickled) == _node_recs(ref)

        # by default only binaries with more than 1 MB of code are paged; an explicit None always stays resident
        assert ref_proj.executable_bytes() < 1024 * 1024 and ref_proj.get_cfg_segment_budget() is None
        with mock.patch.object(angr.Project, "executable_bytes", return_value=2 * 1024 * 1024):
            assert ref_proj.get_cfg_segment_budget() == 128 * 1024 * 1024
        resident = angr.Project(binary, auto_load_libs=False, cache_limits={"cfg_segment_bytes": None})
        assert resident.get_cfg_segment_budget() is None
        assert not resident.analyses.CFGFast(normalize=True).model.graph.paged


if __name__ == "__main__":
    unittest.main()
