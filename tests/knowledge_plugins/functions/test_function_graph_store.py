#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import pickle
import unittest

from angr.rustylib.function_graph import (
    PRESENT_CONFIRMED,
    PRESENT_INS_ADDR,
    PRESENT_OUTSIDE,
    PRESENT_STMT_IDX,
    PRESENT_TYPE,
    EdgeKind,
    EndpointKind,
    FunctionGraph,
    NodeKind,
    SiteKind,
)

ALL = PRESENT_TYPE | PRESENT_OUTSIDE | PRESENT_INS_ADDR | PRESENT_STMT_IDX


def _sample():
    g = FunctionGraph(0x1000)
    a, _, _, _ = g.register_node(True, NodeKind.BLOCK, 0x1000, 8, False)
    b, _, _, _ = g.register_node(True, NodeKind.BLOCK, 0x1008, 4, False)
    c, _, _, _ = g.register_node(False, NodeKind.BLOCK, 0x2000, 16, False)
    f, _ = g.add_node(NodeKind.FUNC, 0x3000, 0, False)
    g.add_edge(a, b, EdgeKind.TRANSITION, ALL, False, 0x1004, -2, False)
    g.add_edge(b, f, EdgeKind.CALL, PRESENT_TYPE | PRESENT_INS_ADDR | PRESENT_STMT_IDX, False, 0x1009, None, False)
    g.add_edge(b, c, EdgeKind.TRANSITION, ALL, True, 0x100A, -2, False)
    g.add_site(b, SiteKind.JUMPOUT)
    g.add_endpoint(b, EndpointKind.TRANSITION)
    g.add_call_site(0x1008, 0x3000, None)
    return g, (a, b, c, f)


class TestFunctionGraphStore(unittest.TestCase):
    def test_register_node_semantics(self):
        g = FunctionGraph(0x1000)
        idx, created, new_local, changed = g.register_node(True, NodeKind.BLOCK, 0x1000, 8, False)
        assert (created, new_local, changed) == (True, True, True)
        assert g.startpoint == idx
        assert g.local_at(0x1000) == idx
        assert g.block_node_at(0x1000) == idx
        assert g.block_size(0x1000) == 8
        assert g.contains_node(idx)
        # registering an equal local node again is a no-op
        assert g.register_node(True, NodeKind.BLOCK, 0x1000, 8, False) == (idx, False, False, False)
        # a different node at a known address is recorded but, like networkx before, only enters the graph via an edge
        idx2, created, new_local, changed = g.register_node(True, NodeKind.BLOCK, 0x1000, 4, False)
        assert idx2 != idx and created and not new_local and changed
        assert not g.contains_node(idx2)
        assert g.local_at(0x1000) == idx  # first local wins
        assert g.block_size(0x1000) == 8
        g.add_edge(idx, idx2, EdgeKind.TRANSITION, PRESENT_TYPE)
        assert g.contains_node(idx2)
        # a hook startpoint is not replaced by a block
        h = FunctionGraph(0x1000)
        hidx, _, _, _ = h.register_node(True, NodeKind.HOOK, 0x1000, 0, False)
        h.register_node(True, NodeKind.BLOCK, 0x1000, 8, False)
        assert h.startpoint == hidx

    def test_edges_iteration_and_degrees(self):
        g, (a, b, c, f) = _sample()
        assert g.number_of_nodes() == 4
        assert g.number_of_edges() == 3
        assert g.nodes() == [a, b, c, f]
        assert g.edges() == [(a, b), (b, f), (b, c)]
        assert g.successors(b) == [f, c]
        assert g.predecessors(c) == [b]
        assert g.out_degree(b) == 2 and g.in_degree(b) == 1
        assert g.edge_data(a, b) == {"type": "transition", "outside": False, "ins_addr": 0x1004, "stmt_idx": -2}
        assert g.edge_data(b, f) == {"type": "call", "ins_addr": 0x1009, "stmt_idx": None}
        assert g.edge_kind(b, f) == EdgeKind.CALL
        assert g.edge_is_outside(b, c) is True
        assert g.edges_of_kind(EdgeKind.CALL) == [(b, f)]
        assert [(u, v) for u, v, _ in g.local_edges_with_data()] == [(a, b)]
        assert g.outgoing_function_targets() == [(0x2000, False), (0x3000, True)]
        assert g.find_node(NodeKind.BLOCK, 0x1008, 4, False) == b
        assert g.find_node(NodeKind.BLOCK, 0x1008, 5, False) is None

    def test_add_edge_merges_attributes(self):
        g, (a, b, _, _) = _sample()
        assert not g.add_edge(a, b, EdgeKind.FAKE_RETURN, PRESENT_TYPE | PRESENT_CONFIRMED, confirmed=True)
        assert g.edge_data(a, b) == {
            "type": "fake_return",
            "outside": False,
            "ins_addr": 0x1004,
            "stmt_idx": -2,
            "confirmed": True,
        }
        g.set_edge_confirmed(a, b, False)
        assert g.edge_confirmed(a, b) is False
        assert g.number_of_edges() == 3

    def test_remove_edge_and_node(self):
        g, (a, b, c, f) = _sample()
        assert g.remove_edge(b, f)
        assert not g.remove_edge(b, f)
        assert g.edges() == [(a, b), (b, c)]
        assert g.remove_node(b)
        assert g.edges() == []
        assert g.nodes() == [a, c, f]
        # the maps still refer to the record, as the old dicts kept referring to the node object
        assert g.local_at(0x1008) == b
        assert g.block_size(0x1008) == 4
        assert g.sites(SiteKind.JUMPOUT) == [b]

    def test_sites_endpoints_call_sites(self):
        g, (_, b, _, _) = _sample()
        assert g.sites(SiteKind.JUMPOUT) == [b]
        assert g.sites(SiteKind.RET) == []
        assert g.has_site(b, SiteKind.JUMPOUT)
        assert g.endpoints(EndpointKind.TRANSITION) == [b]
        assert g.has_any_endpoint()
        assert g.call_sites() == [(0x1008, 0x3000, None)]
        assert g.call_site(0x1008) == (0x3000, None)
        assert g.call_site(0x1000) is None
        assert g.local_addrs() == [0x1000, 0x1008]
        assert g.local_count() == 2
        assert g.local_size() == 12

    def test_bytes_round_trip(self):
        g, (a, b, c, _) = _sample()
        g.remove_node(c)  # a ghost record that only the local maps keep alive must survive compaction
        data = g.to_bytes()
        assert isinstance(data, bytes) and data[0] == 2
        h = FunctionGraph.from_bytes(data)
        assert h.func_addr == 0x1000
        assert [h.node(i) for i in h.nodes()] == [g.node(i) for i in g.nodes()]
        assert [(h.node(u), h.node(v), d) for u, v, d in h.edges_with_data()] == [
            (g.node(u), g.node(v), d) for u, v, d in g.edges_with_data()
        ]
        assert h.local_addrs() == g.local_addrs()
        assert h.node(h.startpoint) == g.node(a)
        assert h.node(h.sites(SiteKind.JUMPOUT)[0]) == g.node(b)
        assert h.call_sites() == g.call_sites()
        assert h.block_size(0x2000) == 16
        assert FunctionGraph.local_block_addrs_from_bytes(data) == [0x1000, 0x1008]
        assert h.to_bytes() == data
        assert pickle.loads(pickle.dumps(h)).to_bytes() == data
        assert g.copy().to_bytes() == data
        with self.assertRaises(ValueError):
            FunctionGraph.from_bytes(b"\x07\x00")

    def test_normalize_splits_overlapping_blocks(self):
        g = FunctionGraph(0x1000)
        big, _, _, _ = g.register_node(True, NodeKind.BLOCK, 0x1000, 0x10, False)
        small, _, _, _ = g.register_node(True, NodeKind.BLOCK, 0x1008, 0x8, False)
        tail, _, _, _ = g.register_node(True, NodeKind.BLOCK, 0x1010, 0x4, False)
        g.add_edge(big, tail, EdgeKind.TRANSITION, ALL, False, 0x100E, -2, False)
        g.add_edge(small, tail, EdgeKind.TRANSITION, ALL, False, 0x100E, -2, False)
        g.add_site(big, SiteKind.RET)
        g.add_endpoint(big, EndpointKind.RETURN)
        g.normalize(False, lambda addr, size: addr + size - 2)
        head = g.local_at(0x1000)
        assert head != big
        assert g.node(head) == (NodeKind.BLOCK, 0x1000, 8, False)
        assert g.block_size(0x1000) == 8
        assert g.block_node_at(0x1000) == head
        assert g.startpoint == head
        assert not g.contains_node(big)
        assert g.edge_data(head, small) == {"type": "transition", "outside": False, "ins_addr": 0x1006}
        assert sorted(g.edges()) == sorted([(head, small), (small, tail)])
        assert g.sites(SiteKind.RET) == [small]
        assert g.endpoints(EndpointKind.RETURN) == [small]


if __name__ == "__main__":
    unittest.main()
