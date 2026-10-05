# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""
Tests for the memory-optimized per-node bookkeeping of SpillingCFG: canonical block-key interning, the shared
spilled-key flags dict (KeyFlagSet), the single-key-or-set representation of _keys_by_addr, and the shared empty
node-attribute dict.
"""

from __future__ import annotations

import pickle
import unittest

from angr.knowledge_plugins.cfg.cfg_node import CFGNode
from angr.knowledge_plugins.cfg.spilling_cfg import SpillingCFG, get_block_key
from angr.knowledge_plugins.cfg.spilling_digraph import KeyFlagSet


def _make_graph(n: int = 50) -> tuple[SpillingCFG, list[CFGNode]]:
    g = SpillingCFG(rtdb=None, cfg_model=None)
    nodes = []
    for i in range(n):
        node = CFGNode(0x400000 + i * 0x10, 16, None, block_id=0x400000 + i * 0x10)
        nodes.append(node)
        g.add_node(node)
    for i in range(n - 1):
        g.add_edge(nodes[i], nodes[i + 1], jumpkind="Ijk_Boring", ins_addr=nodes[i].addr, stmt_idx=1)
    if n > 10:
        g.add_edge(nodes[0], nodes[10], jumpkind="Ijk_Call", ins_addr=nodes[0].addr, stmt_idx=2)
    return g, nodes


class TestKeyFlagSet(unittest.TestCase):
    def test_basic_set_semantics(self):
        flags: dict = {}
        a = KeyFlagSet(flags, 0b01)
        b = KeyFlagSet(flags, 0b10)

        a.add((1, 2))
        b.add((1, 2))
        b.add((3, 4))
        assert (1, 2) in a and (1, 2) in b
        assert (3, 4) not in a and (3, 4) in b
        assert len(a) == 1 and len(b) == 2
        # both containers share a single dict entry for (1, 2)
        assert len(flags) == 2

        a.discard((1, 2))
        assert (1, 2) not in a and (1, 2) in b
        a.discard((1, 2))  # discarding twice is a no-op
        assert len(a) == 0 and not a
        assert sorted(b) == [(1, 2), (3, 4)]

        b.clear()
        assert len(b) == 0 and not flags


class TestNodeKeySkeleton(unittest.TestCase):
    def test_key_interning_across_containers(self):
        g, _ = _make_graph()
        gr = g._graph
        ids_node = {id(k) for k in gr._node}
        assert {id(k) for k in g._nodes._data} == ids_node
        assert {id(k) for k in gr._adj._data} <= ids_node
        assert {id(k) for k in gr._pred._data} <= ids_node
        assert {id(k) for k in g._out_degree_cache} <= ids_node
        assert {id(k) for k in g._call_dst_keys} <= ids_node
        # inner adjacency keys are canonical as well
        for inner in gr._adj._data.values():
            for dst_key in inner:
                assert id(dst_key) in ids_node

    def test_shared_spill_flags(self):
        g, _ = _make_graph()
        assert g._nodes._spilled_keys.flags is g._graph._adj._spilled_keys.flags
        assert g._nodes._spilled_keys.flags is g._graph._pred._spilled_keys.flags

    def test_shared_empty_node_attr_dicts(self):
        g, nodes = _make_graph()
        attr_dict_ids = {id(d) for d in g._graph._node.values()}
        assert len(attr_dict_ids) == 1
        with self.assertRaises(TypeError):
            g._graph._node[get_block_key(nodes[0])]["x"] = 1

    def test_node_attrs_materialize_when_supplied(self):
        g, _ = _make_graph(2)
        node = CFGNode(0x500000, 8, None, block_id=0x500000)
        g.add_node(node, color="red")
        assert g._graph._node[get_block_key(node)] == {"color": "red"}

    def test_keys_by_addr_promotion_and_removal(self):
        g, _ = _make_graph(2)
        na = CFGNode(0x600000, 8, None, block_id=0x600000)
        nb = CFGNode(0x600000, 16, None, block_id=0x600000)
        g.add_node(na)
        assert not isinstance(g._keys_by_addr[0x600000], set)
        g.add_node(nb)
        assert isinstance(g._keys_by_addr[0x600000], set)
        assert sorted(n.size for n in g.nodes_by_addr(0x600000)) == [8, 16]
        g.remove_node(na)
        assert [n.size for n in g.nodes_by_addr(0x600000)] == [16]
        g.remove_node(nb)
        assert not g.has_node_addr(0x600000)
        assert 0x600000 not in g._keys_by_addr

    def test_copy_preserves_content_and_rewires(self):
        g, nodes = _make_graph()
        g2 = g.copy()
        assert len(g2) == len(g)
        assert g2.number_of_edges() == g.number_of_edges()
        assert g2.get_edge_data(nodes[0], nodes[10])["jumpkind"] == "Ijk_Call"
        assert g2._nodes._spilled_keys.flags is g2._graph._adj._spilled_keys.flags

    def test_pickle_roundtrip(self):
        g, nodes = _make_graph()
        g2 = pickle.loads(pickle.dumps(g))
        assert len(g2) == len(g)
        assert g2.number_of_edges() == g.number_of_edges()
        assert g2.get_edge_data(nodes[0], nodes[10])["jumpkind"] == "Ijk_Call"
        assert sorted(n.addr for n in g2.nodes()) == sorted(n.addr for n in g.nodes())
        # after unpickling, spill bookkeeping is re-shared and node attr dicts are shared again
        assert g2._nodes._spilled_keys.flags is g2._graph._adj._spilled_keys.flags
        assert len({id(d) for d in g2._graph._node.values()}) == 1


if __name__ == "__main__":
    unittest.main()
