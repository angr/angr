#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr import ailment
from angr.analyses.decompiler.structurer_nodes import BreakNode, CodeNode, LoopNode, SequenceNode


class TestStructurerNodeAddresses(unittest.TestCase):
    def test_codenode_addr_is_fixed_at_construction(self):
        node = CodeNode(ailment.Block(0x400000, 0), None)
        assert node.addr == 0x400000

        # replacing the inner node must not move the CodeNode
        node.node = SequenceNode(0x400100, nodes=[])
        assert node.addr == 0x400000

    def test_codenode_addr_is_none_without_an_inner_addr(self):
        assert CodeNode(None, None).addr is None

    def test_codenode_copy_preserves_addr(self):
        node = CodeNode(ailment.Block(0x400000, 0, idx=3), None)
        assert (node.addr, node.idx) == (0x400000, 3)
        assert (node.copy().addr, node.copy().idx) == (0x400000, 3)

    def test_loopnode_addr_is_fixed_at_construction(self):
        loop = LoopNode("while", None, SequenceNode(0x400000, nodes=[]))
        assert loop.addr == 0x400000
        assert loop.continue_addr == 0x400000

        loop.sequence_node = SequenceNode(0x400100, nodes=[])
        assert loop.addr == 0x400000

    def test_loopnode_explicit_addrs_win_and_survive_copy(self):
        loop = LoopNode("while", None, SequenceNode(0x400100, nodes=[]), addr=0x400000, continue_addr=0x400080)
        assert (loop.addr, loop.continue_addr) == (0x400000, 0x400080)
        copied = loop.copy()
        assert (copied.addr, copied.continue_addr) == (0x400000, 0x400080)


class TestStructurerNodeHashing(unittest.TestCase):
    """Structurer nodes must not fall back to object.__hash__: an id()-derived hash makes the iteration order of
    RegionOverlay._members (and every other set of structurer nodes) differ between runs, which in turn changes the
    decompiler output. See the region member ordering in RecursiveStructurer._structure_overlay_tree."""

    def test_hash_does_not_depend_on_object_identity(self):
        addrs = [0x400000 + i * 0x10 for i in range(64)]
        first = [n.addr for n in {SequenceNode(addr, nodes=[]) for addr in addrs}]
        second = [n.addr for n in {SequenceNode(addr, nodes=[]) for addr in addrs}]
        assert first == second

    def test_hash_is_stable_under_in_place_editing(self):
        seq = SequenceNode(0x400000, nodes=[])
        loop = LoopNode("while", None, seq)
        code = CodeNode(seq, None)
        members = {seq, loop, code}
        hashes = [hash(seq), hash(loop), hash(code)]

        seq.add_node(ailment.Block(0x400010, 0))
        seq.addr = 0x400010
        loop.sequence_node = SequenceNode(0x400020, nodes=[])
        code.node = SequenceNode(0x400020, nodes=[])

        assert [hash(seq), hash(loop), hash(code)] == hashes
        assert all(node in members for node in (seq, loop, code))

    def test_distinct_nodes_sharing_an_address_stay_distinct(self):
        a = SequenceNode(0x400000, nodes=[])
        b = SequenceNode(0x400000, nodes=[])
        assert a != b
        assert len({a, b}) == 2

        d = {a: "a", b: "b"}
        assert len(d) == 2
        assert d[a] == "a"
        assert d[b] == "b"

    def test_node_type_participates_in_the_hash(self):
        assert hash(SequenceNode(0x400000, nodes=[])) != hash(BreakNode(0x400000, None))


if __name__ == "__main__":
    unittest.main()
