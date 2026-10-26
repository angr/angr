#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""Nodes that share (kind, addr, size, thumb) but carry different block IDs stay distinct (VM deobfuscation)."""

from __future__ import annotations

import pickle
import unittest

import angr
from angr.codenode import BlockNode
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.functions import Function


def _func(addr: int = 0x1000) -> Function:
    proj = angr.load_shellcode(b"\x90" * 0x20, arch="AMD64", load_address=0x1000)
    func = proj.kb.functions.function(addr, create=True)
    assert func is not None
    return func


class TestFunctionBlockIdDisc(unittest.TestCase):
    def test_block_ids_keep_nodes_apart(self):
        func = _func()
        vpc1 = BlockID(0x1000, None, "normal", vm_vpc=1)
        vpc2 = BlockID(0x1000, None, "normal", vm_vpc=2)
        a = BlockNode(0x1000, 4, block_id=vpc1)
        b = BlockNode(0x1000, 4, block_id=vpc2)
        c = BlockNode(0x1004, 4)
        func.transit_to(a, c)
        func.transit_to(c, b)

        tg = func.transition_graph
        assert tg.number_of_nodes() == 3
        assert list(tg.successors(a)) == [c]
        assert list(tg.successors(c)) == [b]
        assert func.startpoint is a
        assert func.has_node(BlockNode(0x1000, 4, block_id=BlockID(0x1000, None, "normal", vm_vpc=2)))
        assert not func.has_node(BlockNode(0x1000, 4))
        assert not func.has_node(BlockNode(0x1000, 4, block_id=BlockID(0x1000, None, "normal", vm_vpc=3)))

        func.remove_graph_node(b)
        assert func.transition_graph.number_of_nodes() == 2

        # rebuilt node objects carry their block IDs
        for f in (func.copy(), pickle.loads(pickle.dumps(func))):
            nodes = {n.block_id for n in f.transition_graph.nodes()}
            assert nodes == {vpc1, None}
            assert f.has_node(BlockNode(0x1000, 4, block_id=vpc1))
            assert f._graph.to_bytes()[0] == 0x82

    def test_no_block_id_unchanged(self):
        func = _func()
        a = BlockNode(0x1000, 4)
        func.transit_to(a, BlockNode(0x1004, 4))
        func.transit_to(BlockNode(0x1000, 4), BlockNode(0x1008, 4))
        assert func.transition_graph.number_of_nodes() == 3
        assert func._block_ids is None
        assert func._graph.to_bytes()[0] == 2
        assert func.size == 12

    def test_cfgenode_is_canonical(self):
        func = _func()
        bid = BlockID(0x1000, None, "normal", vm_vpc=7)
        node = CFGENode(0x1000, None, None, block_id=bid, instruction_addrs=[0x1000])
        func.register_node(True, node)
        succ = CFGENode(0x1010, 4, None, block_id=BlockID(0x1010, None, "normal", vm_vpc=7))
        func.transit_to(node, succ)

        assert func.startpoint is node
        assert func.get_node(0x1000) is node
        assert any(n is node for n in func.transition_graph.nodes())
        assert next(iter(func.transition_graph.predecessors(succ))) is node
        # size None counts as 0
        assert func.size == 4


if __name__ == "__main__":
    unittest.main()
