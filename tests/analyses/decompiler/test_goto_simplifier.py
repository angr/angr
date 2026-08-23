#!/usr/bin/env python3
# pylint:disable=protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace
from typing import Any, cast

import networkx

from angr.ailment import Block
from angr.ailment.expression import Const
from angr.ailment.statement import ConditionalJump, Jump, Label
from angr.analyses.decompiler.goto_manager import Goto, GotoManager
from angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter import DuplicationReverter
from angr.analyses.decompiler.region_simplifiers.goto import GotoSimplifier
from angr.analyses.decompiler.structurer_nodes import LoopNode, SequenceNode


def _jump_block(addr, idx, target_addr, target_idx, ins_addr=None):
    tags = {} if ins_addr is None else {"ins_addr": ins_addr}
    return Block(
        addr,
        4,
        statements=[Jump(0, Const(1, target_addr, 64), target_idx=target_idx, **tags)],
        idx=idx,
    )


def _tagged_block(addr, idx, ins_addr):
    return Block(addr, 4, statements=[Label(0, f"LABEL_{addr:x}", ins_addr=ins_addr)], idx=idx)


class TestGotoSimplifier(unittest.TestCase):  # pylint:disable=missing-class-docstring
    def test_irreducible_unconditional_goto_preserves_target_idx(self):
        source = _jump_block(0x1000, 0, 0x2000, 2)
        sibling = Block(0x2000, 4, idx=3)
        target = Block(0x2000, 4, idx=2)

        simplifier = GotoSimplifier(SequenceNode(0x1000, [source, sibling, target]), function=object())

        self.assertIsInstance(source.statements[-1], Jump)
        self.assertEqual(
            {(goto.src_idx, goto.dst_addr, goto.dst_idx) for goto in simplifier.irreducible_gotos},
            {(0, 0x2000, 2)},
        )

    def test_same_address_sibling_does_not_mask_missing_target(self):
        source = _jump_block(0x1000, 0, 0x2000, 2)
        sibling = Block(0x2000, 4, idx=3)

        simplifier = GotoSimplifier(SequenceNode(0x1000, [source, sibling]), function=object())

        self.assertEqual(source.statements, [])
        self.assertEqual(simplifier.irreducible_gotos, set())

    def test_exact_successor_identity_removes_jump(self):
        source = _jump_block(0x1000, 0, 0x2000, 2)
        target = Block(0x2000, 4, idx=2)

        GotoSimplifier(SequenceNode(0x1000, [source, target]), function=object())

        self.assertEqual(source.statements, [])

    def test_none_target_idx_is_exact_block_identity(self):
        source = _jump_block(0x1000, 0, 0x2000, None)
        indexed_sibling = Block(0x2000, 4, idx=1)
        target = Block(0x2000, 4, idx=None)

        simplifier = GotoSimplifier(SequenceNode(0x1000, [source, indexed_sibling, target]), function=object())

        self.assertIsInstance(source.statements[-1], Jump)
        self.assertEqual(
            {(goto.dst_addr, goto.dst_idx) for goto in simplifier.irreducible_gotos},
            {(0x2000, None)},
        )

    def test_none_target_idx_matches_only_none_successor(self):
        source = _jump_block(0x1000, 0, 0x2000, None)
        target = Block(0x2000, 4, idx=None)

        GotoSimplifier(SequenceNode(0x1000, [source, target]), function=object())

        self.assertEqual(source.statements, [])

    def test_indexed_target_does_not_match_none_successor(self):
        source = _jump_block(0x1000, 0, 0x2000, 2)
        unindexed_sibling = Block(0x2000, 4, idx=None)
        target = Block(0x2000, 4, idx=2)

        simplifier = GotoSimplifier(SequenceNode(0x1000, [source, unindexed_sibling, target]), function=object())

        self.assertIsInstance(source.statements[-1], Jump)
        self.assertEqual({goto.dst_idx for goto in simplifier.irreducible_gotos}, {2})

    def test_successor_without_idx_uses_address_compatibility(self):
        source = _jump_block(0x1000, 0, 0x2000, 7)
        structured_successor = SequenceNode(0x2000, [])

        GotoSimplifier(SequenceNode(0x1000, [source, structured_successor]), function=object())

        self.assertEqual(source.statements, [])

    def test_sequence_successor_uses_entry_block_identity(self):
        source = _jump_block(0x1000, 0, 0x2000, 2)
        wrapped_sibling = SequenceNode(0x2000, [Block(0x2000, 4, idx=3)])
        target = Block(0x2000, 4, idx=2)

        simplifier = GotoSimplifier(SequenceNode(0x1000, [source, wrapped_sibling, target]), function=object())

        self.assertIsInstance(source.statements[-1], Jump)
        self.assertEqual({goto.dst_idx for goto in simplifier.irreducible_gotos}, {2})

    def test_loop_successor_uses_body_entry_block_identity(self):
        loop_entry = Block(0x2000, 4, idx=3)
        latch = _jump_block(0x2100, 0, 0x2000, 2)
        loop = LoopNode("while", Const(0, 1, 1), SequenceNode(0x2000, [loop_entry, latch]), addr=0x2000)
        target = Block(0x2000, 4, idx=2)

        simplifier = GotoSimplifier(SequenceNode(0x2000, [loop, target]), function=object())

        self.assertIsInstance(latch.statements[-1], Jump)
        self.assertEqual({goto.dst_idx for goto in simplifier.irreducible_gotos}, {2})

    def test_irreducible_conditional_gotos_preserve_target_indices(self):
        block = Block(
            0x1000,
            4,
            statements=[
                ConditionalJump(
                    0,
                    Const(1, 1, 1),
                    Const(2, 0x2000, 64),
                    Const(3, 0x2000, 64),
                    true_target_idx=4,
                    false_target_idx=5,
                    ins_addr=0x1003,
                )
            ],
            idx=3,
        )

        simplifier = GotoSimplifier(block, function=object())

        self.assertEqual(
            {(goto.src_idx, goto.dst_addr, goto.dst_idx) for goto in simplifier.irreducible_gotos},
            {(3, 0x2000, 4), (3, 0x2000, 5)},
        )


class TestGotoManager(unittest.TestCase):  # pylint:disable=missing-class-docstring
    def test_gotos_in_block_uses_exact_source_identity(self):
        sibling = _tagged_block(0x1000, 1, 0x1003)
        source = _tagged_block(0x1000, 2, 0x1003)
        unindexed_source = _tagged_block(0x1000, None, 0x1003)
        goto = Goto(0x1000, 0x2000, src_idx=2, dst_idx=4, src_ins_addr=0x1003)
        none_idx_goto = Goto(0x1000, 0x3000, src_idx=None, dst_idx=5, src_ins_addr=0x1003)
        manager = GotoManager(SimpleNamespace(addr=0x1000), {goto, none_idx_goto})

        self.assertEqual(manager.gotos_in_block(sibling), set())
        self.assertEqual(manager.gotos_in_block(source), {goto})
        self.assertEqual(manager.gotos_in_block(unindexed_source), {none_idx_goto})

    def test_gotos_in_block_falls_back_for_shifted_source(self):
        shifted_source = _tagged_block(0x1100, 7, 0x1003)
        goto = Goto(0x1000, 0x2000, src_idx=2, dst_idx=4, src_ins_addr=0x1003)
        manager = GotoManager(SimpleNamespace(addr=0x1000), {goto})
        graph = networkx.DiGraph()
        graph.add_node(shifted_source)

        self.assertEqual(manager.gotos_in_block(shifted_source, graph=graph), {goto})

        duplicate = _tagged_block(0x1200, 8, 0x1003)
        graph.add_node(duplicate)
        self.assertEqual(manager.gotos_in_block(shifted_source, graph=graph), set())
        self.assertEqual(manager.gotos_in_block(duplicate, graph=graph), set())

    def test_exact_source_suppresses_instruction_fallback(self):
        source = _tagged_block(0x1000, 2, 0x1003)
        shifted_source = _tagged_block(0x1100, 7, 0x1003)
        goto = Goto(0x1000, 0x2000, src_idx=2, dst_idx=4, src_ins_addr=0x1003)
        manager = GotoManager(SimpleNamespace(addr=0x1000), {goto})
        graph = networkx.DiGraph()
        graph.add_nodes_from([source, shifted_source])

        self.assertEqual(manager.gotos_in_block(source, graph=graph), {goto})
        self.assertEqual(manager.gotos_in_block(shifted_source, graph=graph), set())

    def test_is_goto_edge_uses_exact_destination_identity(self):
        source = _tagged_block(0x1000, 2, 0x1003)
        sibling = _tagged_block(0x2000, 1, 0x2003)
        unindexed_sibling = _tagged_block(0x2000, None, 0x2003)
        target = _tagged_block(0x2000, 2, 0x2003)
        goto = Goto(0x1000, 0x2000, src_idx=2, dst_idx=2, src_ins_addr=0x1003)
        manager = GotoManager(SimpleNamespace(addr=0x1000), {goto})

        self.assertFalse(manager.is_goto_edge(source, sibling))
        self.assertFalse(manager.is_goto_edge(source, unindexed_sibling))
        self.assertTrue(manager.is_goto_edge(source, target))

        none_target = _tagged_block(0x3000, None, 0x3003)
        none_goto = Goto(0x1000, 0x3000, src_idx=2, dst_idx=None, src_ins_addr=0x1003)
        manager = GotoManager(SimpleNamespace(addr=0x1000), {none_goto})
        self.assertTrue(manager.is_goto_edge(source, none_target))

    def test_is_goto_edge_uses_unique_shifted_destination(self):
        source = _tagged_block(0x1000, 2, 0x1003)
        same_address_sibling = _tagged_block(0x2000, 1, 0x2003)
        shifted_target = _tagged_block(0x2100, 7, 0x2000)
        goto = Goto(0x1000, 0x2000, src_idx=2, dst_idx=2, src_ins_addr=0x1003)
        manager = GotoManager(SimpleNamespace(addr=0x1000), {goto})
        graph = networkx.DiGraph()
        graph.add_nodes_from([source, same_address_sibling, shifted_target])

        self.assertTrue(manager.is_goto_edge(source, shifted_target, graph=graph))
        self.assertFalse(manager.is_goto_edge(source, same_address_sibling, graph=graph))

        duplicate = _tagged_block(0x2200, 8, 0x2000)
        graph.add_node(duplicate)
        self.assertFalse(manager.is_goto_edge(source, shifted_target, graph=graph))
        self.assertFalse(manager.is_goto_edge(source, duplicate, graph=graph))

    def test_find_goto_edges_uses_exact_siblings(self):
        source_1 = _tagged_block(0x1000, 1, 0x1003)
        source_2 = _tagged_block(0x1000, 2, 0x1003)
        target_1 = _tagged_block(0x2000, 1, 0x2003)
        target_2 = _tagged_block(0x2000, 2, 0x2003)
        graph = networkx.DiGraph()
        graph.add_nodes_from([source_1, source_2, target_1, target_2])
        gotos = {
            Goto(0x1000, 0x2000, src_idx=1, dst_idx=1, src_ins_addr=0x1003),
            Goto(0x1000, 0x2000, src_idx=2, dst_idx=2, src_ins_addr=0x1003),
            Goto(0x1000, 0x2000, src_idx=3, dst_idx=2, src_ins_addr=0x1003),
        }
        manager = GotoManager(SimpleNamespace(addr=0x1000), gotos)

        self.assertEqual(
            set(manager.find_goto_edges(graph)),
            {(source_1, target_1), (source_2, target_2)},
        )

    def test_find_goto_edges_requires_unique_shifted_source(self):
        same_address_sibling = _tagged_block(0x1000, 9, 0x1003)
        shifted = _tagged_block(0x1100, 1, 0x1003)
        duplicate = _tagged_block(0x1200, 2, 0x1003)
        target = _tagged_block(0x2000, 4, 0x2003)
        graph = networkx.DiGraph()
        graph.add_nodes_from([same_address_sibling, shifted, target])
        goto = Goto(0x1000, 0x2000, src_idx=3, dst_idx=4, src_ins_addr=0x1003)
        manager = GotoManager(SimpleNamespace(addr=0x1000), {goto})
        self.assertEqual(manager.find_goto_edges(graph), [(shifted, target)])

        graph.add_node(duplicate)
        self.assertEqual(manager.find_goto_edges(graph), [])

    def test_find_goto_edges_requires_unique_shifted_destination(self):
        source = _tagged_block(0x1000, 3, 0x1003)
        shifted = _tagged_block(0x2100, 1, 0x2000)
        duplicate = _tagged_block(0x2200, 2, 0x2000)
        graph = networkx.DiGraph()
        graph.add_nodes_from([source, shifted])
        goto = Goto(0x1000, 0x2000, src_idx=3, dst_idx=4, src_ins_addr=0x1003)
        manager = GotoManager(SimpleNamespace(addr=0x1000), {goto})

        self.assertEqual(manager.find_goto_edges(graph), [(source, shifted)])

        graph.add_node(duplicate)
        self.assertEqual(manager.find_goto_edges(graph), [])


class TestDuplicationReverterGotoResolution(unittest.TestCase):  # pylint:disable=missing-class-docstring
    @staticmethod
    def _reverter(graph, goto):
        reverter = object.__new__(DuplicationReverter)
        reverter._goto_manager = GotoManager(SimpleNamespace(addr=0x1000), {goto})
        reverter.out_graph = graph
        return cast(Any, reverter)

    def test_block_goto_edge_selects_exact_destination_sibling(self):
        source = _jump_block(0x1000, 0, 0x2000, 2, ins_addr=0x1003)
        sibling = _tagged_block(0x2000, 1, 0x2003)
        target = _tagged_block(0x2000, 2, 0x2003)
        graph = networkx.DiGraph()
        graph.add_nodes_from([source, sibling, target])
        graph.add_edges_from([(source, sibling), (source, target)])
        goto = Goto(0x1000, 0x2000, src_idx=0, dst_idx=2, src_ins_addr=0x1003)
        reverter = self._reverter(graph, goto)

        self.assertTrue(reverter._block_has_goto_edge(source, [target], graph))
        self.assertFalse(reverter._block_has_goto_edge(source, [sibling], graph))

    def test_block_goto_edge_requires_unique_shifted_destination(self):
        source = _jump_block(0x1000, 0, 0x2000, 2, ins_addr=0x1003)
        same_address_sibling = _tagged_block(0x2000, 1, 0x2003)
        shifted = _tagged_block(0x2100, 3, 0x2000)
        duplicate = _tagged_block(0x2200, 4, 0x2000)
        graph = networkx.DiGraph()
        graph.add_nodes_from([source, same_address_sibling, shifted])
        goto = Goto(0x1000, 0x2000, src_idx=0, dst_idx=2, src_ins_addr=0x1003)
        reverter = self._reverter(graph, goto)

        self.assertTrue(reverter._block_has_goto_edge(source, [shifted], graph))
        self.assertFalse(reverter._block_has_goto_edge(source, [same_address_sibling], graph))

        graph.add_node(duplicate)
        self.assertFalse(reverter._block_has_goto_edge(source, [shifted], graph))

    def test_future_gotos_resolve_exact_destination(self):
        source = _jump_block(0x1000, 0, 0x2000, 2, ins_addr=0x1003)
        sibling_end = _tagged_block(0x2000, 1, 0x2003)
        target_cycle = _tagged_block(0x2000, 2, 0x2003)
        graph = networkx.DiGraph()
        graph.add_nodes_from([source, sibling_end, target_cycle])
        graph.add_edge(target_cycle, target_cycle)
        goto = Goto(0x1000, 0x2000, src_idx=0, dst_idx=2, src_ins_addr=0x1003)
        reverter = self._reverter(graph, goto)

        self.assertEqual(reverter._find_future_irreducible_gotos(), {goto})

    def test_future_gotos_require_unique_shifted_destination(self):
        source = _jump_block(0x1000, 0, 0x2000, 2, ins_addr=0x1003)
        shifted_cycle = _tagged_block(0x2100, 3, 0x2000)
        duplicate_cycle = _tagged_block(0x2200, 4, 0x2000)
        graph = networkx.DiGraph()
        graph.add_nodes_from([source, shifted_cycle])
        graph.add_edge(shifted_cycle, shifted_cycle)
        goto = Goto(0x1000, 0x2000, src_idx=0, dst_idx=2, src_ins_addr=0x1003)
        reverter = self._reverter(graph, goto)

        self.assertEqual(reverter._find_future_irreducible_gotos(), {goto})

        graph.add_edge(duplicate_cycle, duplicate_cycle)
        self.assertEqual(reverter._find_future_irreducible_gotos(), set())


if __name__ == "__main__":
    unittest.main()
