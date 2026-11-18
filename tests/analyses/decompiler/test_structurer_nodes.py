#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr import ailment, claripy
from angr.analyses.decompiler.empty_node_remover import EmptyNodeRemover
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import (
    BreakNode,
    CascadingConditionNode,
    CodeNode,
    ConditionNode,
    ContinueNode,
    IncompleteSwitchCaseNode,
    LoopNode,
    MultiNode,
    SequenceNode,
)
from angr.analyses.decompiler.utils import insert_node
from angr.utils.hashing import stable_hash


class TestStructurerNodeAddresses(unittest.TestCase):
    def test_codenode_addr_is_fixed_at_construction(self):
        node = CodeNode(ailment.Block(0x400000, 0), None)
        assert node.addr == 0x400000

        # replacing the inner node must not move the CodeNode
        node.node = SequenceNode(0x400100, nodes=[])
        assert node.addr == 0x400000

    def test_codenode_copy_preserves_addr(self):
        node = CodeNode(ailment.Block(0x400000, 0, idx=3), None)
        assert (node.addr, node.idx) == (0x400000, 3)
        assert (node.copy().addr, node.copy().idx) == (0x400000, 3)

    def test_empty_node_remover_keeps_root_addr(self):
        # an all-empty region must not collapse to a sequence at a sentinel address
        root = SequenceNode(0x400000, nodes=[SequenceNode(0x400004, nodes=[])])
        result = EmptyNodeRemover(root, None).result
        assert isinstance(result, SequenceNode)
        assert result.nodes == []
        assert result.addr == 0x400000

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


class TestMultiNodeHashing(unittest.TestCase):
    def test_hash_is_seed_and_identity_independent(self):
        # hash(str) and hash(class) are both process-specific; stable_hash() is neither
        node = MultiNode([ailment.Block(0x400000, 0, idx=2)])
        assert hash(node) == stable_hash((MultiNode, 0x400000, 2))

    def test_hash_is_stable_under_in_place_editing(self):
        node = MultiNode([ailment.Block(0x400000, 0)])
        members = {node}
        h = hash(node)

        node.nodes.append(ailment.Block(0x400010, 0))
        assert hash(node) == h
        assert node in members

    def test_distinct_nodes_sharing_an_address_hash_alike(self):
        assert hash(MultiNode([ailment.Block(0x400000, 0)])) == hash(MultiNode([ailment.Block(0x400000, 0)]))


class TestMultiNodeHoldsBlocksOnly(unittest.TestCase):
    @staticmethod
    def _insert_after(target, new_node):
        def _handle_Block(block, parent=None, index: int = 0, label=None):
            if block is target:
                insert_node(parent, "after", new_node, index, label=label)

        return SequenceWalker(handlers={ailment.Block: _handle_Block})

    @staticmethod
    def _insert_continue_after(target):
        return TestMultiNodeHoldsBlocksOnly._insert_after(target, ContinueNode(0x400000, 0x400000))

    def test_insertion_next_to_a_block_replaces_the_multinode_with_a_sequence(self):
        b0, b1 = ailment.Block(0x400000, 4), ailment.Block(0x400004, 4)
        multinode = MultiNode([b0, b1])
        root = SequenceNode(0x400000, nodes=[multinode])

        self._insert_continue_after(b0).walk(root)

        new_node = root.nodes[0]
        assert isinstance(new_node, SequenceNode)
        assert new_node.nodes[0] is b0
        assert isinstance(new_node.nodes[1], ContinueNode)
        assert new_node.nodes[2] is b1
        assert len(multinode.nodes) == 2 and multinode.nodes[0] is b0 and multinode.nodes[1] is b1

    def test_insertion_under_a_root_that_is_not_a_sequence(self):
        # _handle_Condition returns a new ConditionNode rather than updating this root, so the MultiNode has to be
        # replaced in place
        b0, b1 = ailment.Block(0x400000, 4), ailment.Block(0x400004, 4)
        root = ConditionNode(0x400000, None, claripy.true(), MultiNode([b0, b1]))

        self._insert_continue_after(b1).walk(root)

        assert isinstance(root.true_node, SequenceNode)
        assert root.true_node.nodes[0] is b0
        assert root.true_node.nodes[1] is b1
        assert isinstance(root.true_node.nodes[2], ContinueNode)

    def test_insertion_under_a_cascading_condition(self):
        b0, b1 = ailment.Block(0x400000, 4), ailment.Block(0x400004, 4)
        cascading = CascadingConditionNode(0x400000, [(claripy.true(), MultiNode([b0, b1]))])
        root = SequenceNode(0x400000, nodes=[cascading])

        self._insert_continue_after(b1).walk(root)

        new_node = cascading.condition_and_nodes[0][1]
        assert isinstance(new_node, SequenceNode)
        assert new_node.nodes[0] is b0
        assert new_node.nodes[1] is b1
        assert isinstance(new_node.nodes[2], ContinueNode)

    def test_insertion_under_an_incomplete_switch_case_head(self):
        b0, b1 = ailment.Block(0x400000, 4), ailment.Block(0x400004, 4)
        incomplete = IncompleteSwitchCaseNode(0x400000, MultiNode([b0, b1]), [])
        root = SequenceNode(0x400000, nodes=[incomplete])

        self._insert_continue_after(b1).walk(root)

        assert isinstance(incomplete.head, SequenceNode)
        assert incomplete.head.nodes[0] is b0
        assert incomplete.head.nodes[1] is b1
        assert isinstance(incomplete.head.nodes[2], ContinueNode)

    def test_inserting_a_block_keeps_the_multinode(self):
        b0, b1, b2 = ailment.Block(0x400000, 4), ailment.Block(0x400004, 4), ailment.Block(0x400008, 4)
        multinode = MultiNode([b0, b1])
        root = SequenceNode(0x400000, nodes=[multinode])

        self._insert_after(b0, b2).walk(root)

        assert root.nodes[0] is multinode
        assert len(multinode.nodes) == 3
        assert multinode.nodes[0] is b0 and multinode.nodes[1] is b2 and multinode.nodes[2] is b1

    def test_walk_without_insertion_keeps_the_multinode(self):
        multinode = MultiNode([ailment.Block(0x400000, 4), ailment.Block(0x400004, 4)])
        root = SequenceNode(0x400000, nodes=[multinode])

        self._insert_continue_after(None).walk(root)

        assert root.nodes[0] is multinode


if __name__ == "__main__":
    unittest.main()
