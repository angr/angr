#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from collections import defaultdict
from unittest.mock import Mock, patch

import networkx as nx

import angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter as duplication_reverter_module
from angr.ailment import Block, Const, Manager, Register
from angr.ailment.statement import ConditionalJump, Jump, Label
from angr.analyses.decompiler.optimization_passes import DuplicationReverter
from angr.analyses.decompiler.optimization_passes.duplication_reverter.ail_merge_graph import AILMergeGraph
from angr.analyses.decompiler.optimization_passes.duplication_reverter.utils import copy_graph_and_nodes


class TestDuplicationReverter(unittest.TestCase):
    @staticmethod
    def _jump_block(manager, addr, target, *, idx=None, target_idx=None):
        return Block(
            addr,
            1,
            statements=[
                Jump(
                    manager.next_atom(),
                    Const(manager.next_atom(), target, 64),
                    target_idx=target_idx,
                    ins_addr=addr,
                )
            ],
            idx=idx,
        )

    @staticmethod
    def _conditional_block(
        manager,
        addr,
        true_target,
        false_target,
        *,
        idx=None,
        true_target_idx=None,
        false_target_idx=None,
    ):
        return Block(
            addr,
            1,
            statements=[
                ConditionalJump(
                    manager.next_atom(),
                    Const(manager.next_atom(), 1, 1),
                    Const(manager.next_atom(), true_target, 64),
                    Const(manager.next_atom(), false_target, 64),
                    true_target_idx=true_target_idx,
                    false_target_idx=false_target_idx,
                    ins_addr=addr,
                )
            ],
            idx=idx,
        )

    @staticmethod
    def _conditional_targets(statement):
        return (
            (statement.true_target.value, statement.true_target_idx),
            (statement.false_target.value, statement.false_target_idx),
        )

    @staticmethod
    def _reverter(graph, entry_node):
        blocks_by_addr = defaultdict(set)
        for node in graph:
            blocks_by_addr[node.addr].add(node)

        reverter = object.__new__(DuplicationReverter)
        reverter.entry_node_addr = (entry_node.addr, entry_node.idx)
        reverter._blocks_by_addr = blocks_by_addr
        reverter._new_block_addrs = set()
        reverter.read_graph = graph.copy()
        reverter.write_graph = graph
        return reverter

    def _assert_failed_finalization_is_transactional(self, reverter):
        graph = reverter.write_graph
        self.assertIsNotNone(graph)
        assert graph is not None

        def snapshot(candidate):
            def statement_state(statement):
                targets = ()
                if isinstance(statement, Jump):
                    targets = (
                        getattr(statement.target, "value", None),
                        statement.target_idx,
                    )
                elif isinstance(statement, ConditionalJump):
                    targets = self._conditional_targets(statement)
                return id(statement), dict(statement.tags), targets

            return (
                dict(candidate.graph),
                tuple(
                    (
                        id(node),
                        node.addr,
                        node.idx,
                        dict(candidate.nodes[node]),
                        tuple(statement_state(statement) for statement in node.statements),
                    )
                    for node in candidate
                ),
                tuple((id(src), id(dst), dict(data)) for src, dst, data in candidate.edges(data=True)),
            )

        original_state = snapshot(graph)
        original_new_block_addrs = reverter._new_block_addrs.copy()

        self.assertFalse(reverter._finalize_graph_after_reinsertion())

        result_graph = reverter.write_graph
        self.assertIsNotNone(result_graph)
        assert result_graph is not None
        self.assertIsNot(result_graph, reverter.read_graph)
        self.assertEqual(snapshot(graph), original_state)
        self.assertEqual(snapshot(result_graph), original_state)
        self.assertEqual(reverter._new_block_addrs, original_new_block_addrs)

    def test_uniquify_addrs_preserves_designated_entry(self):
        manager = Manager()
        entry = self._jump_block(manager, 0x100, 0x300)
        predecessor = self._jump_block(manager, 0x300, 0x100, target_idx=1)
        duplicate = self._jump_block(manager, 0x100, 0x400, idx=1)
        exit_node = Block(0x400, 1, statements=[])
        graph = nx.DiGraph([(entry, predecessor), (predecessor, duplicate), (duplicate, exit_node)])
        reverter = self._reverter(graph, entry)

        result = reverter._uniquify_addrs(graph, entry)
        self.assertIsNotNone(result)
        assert result is not None

        result_entry = next(node for node in result if (node.addr, node.idx) == reverter.entry_node_addr)
        result_predecessor = next(node for node in result if node.addr == predecessor.addr)
        result_duplicate = next(iter(result.successors(result_predecessor)))

        self.assertIsNot(result_entry, entry)
        self.assertEqual([node for node in result if result.in_degree(node) == 0], [result_entry])
        self.assertEqual(len({node.addr for node in result}), len(result))
        self.assertNotEqual(result_duplicate.addr, duplicate.addr)
        self.assertIsNone(result_duplicate.idx)
        self.assertEqual(result_predecessor.statements[-1].target.value, result_duplicate.addr)
        self.assertEqual(result_entry.statements[-1].tags["ins_addr"], entry.addr)

        self.assertEqual((entry.addr, entry.idx), reverter.entry_node_addr)
        self.assertEqual(duplicate.addr, entry.addr)
        self.assertEqual(duplicate.idx, 1)

    def test_uniquify_addrs_uses_explicit_nonroot_entry(self):
        manager = Manager()
        root_a = self._jump_block(manager, 0x10, 0x100, target_idx=7)
        root_b = self._jump_block(manager, 0x20, 0x100, target_idx=1)
        entry = self._jump_block(manager, 0x100, 0x400, idx=7)
        duplicate = self._jump_block(manager, 0x100, 0xF01, idx=1)
        exit_a = Block(0x400, 1, statements=[])
        exit_b = Block(0xF01, 1, statements=[])
        graph = nx.DiGraph([(root_a, entry), (entry, exit_a), (root_b, duplicate), (duplicate, exit_b)])
        reverter = self._reverter(graph, entry)
        reverter._new_block_addrs.add(0xF00)
        original_jumps = [root_a.statements[-1], root_b.statements[-1], duplicate.statements[-1]]
        original_jump_targets = [
            (jump.target.value, jump.target_idx, dict(jump.tags)) for jump in original_jumps if isinstance(jump, Jump)
        ]

        result = reverter._uniquify_addrs(graph, entry)
        self.assertIsNotNone(result)
        assert result is not None

        result_entry = next(node for node in result if (node.addr, node.idx) == reverter.entry_node_addr)
        result_root_a = next(node for node in result if node.addr == root_a.addr)
        result_root_b = next(node for node in result if node.addr == root_b.addr)
        result_duplicate = next(iter(result.successors(result_root_b)))
        result_root_a_jump = result_root_a.statements[-1]
        result_root_b_jump = result_root_b.statements[-1]
        assert isinstance(result_root_a_jump, Jump)
        assert isinstance(result_root_b_jump, Jump)
        self.assertIsNot(result_root_a_jump, original_jumps[0])
        self.assertIsNot(result_root_b_jump, original_jumps[1])

        self.assertEqual((result_entry.addr, result_entry.idx), (0x100, 7))
        self.assertEqual(result.in_degree(result_entry), 1)
        self.assertEqual({node.addr for node in result if result.in_degree(node) == 0}, {root_a.addr, root_b.addr})
        self.assertNotEqual(result_duplicate.addr, entry.addr)
        self.assertEqual(result_duplicate.addr, 0xF02)
        self.assertIsNone(result_duplicate.idx)
        self.assertEqual(
            (result_root_a_jump.target.value, result_root_a_jump.target_idx),
            (result_entry.addr, result_entry.idx),
        )
        self.assertEqual(
            (result_root_b_jump.target.value, result_root_b_jump.target_idx),
            (result_duplicate.addr, result_duplicate.idx),
        )
        self.assertEqual(len({node.addr for node in result}), len(result))
        self.assertEqual(reverter._new_block_addrs, {0xF00, 0xF02})
        self.assertEqual(
            [
                (jump.target.value, jump.target_idx, dict(jump.tags))
                for jump in original_jumps
                if isinstance(jump, Jump)
            ],
            original_jump_targets,
        )

    def test_uniquify_addrs_maps_conditional_edges_by_address_and_idx(self):
        manager = Manager()
        source = self._conditional_block(
            manager,
            0x10,
            0x100,
            0x100,
            true_target_idx=7,
            false_target_idx=1,
        )
        prefix = Label(manager.next_atom(), "source", ins_addr=source.addr)
        prefix.peephole_optimized = True
        source.statements.insert(0, prefix)
        entry = Block(0x100, 1, statements=[], idx=7)
        duplicate = Block(0x100, 1, statements=[], idx=1)
        graph = nx.DiGraph([(source, duplicate), (source, entry)])
        graph.graph["fixture"] = "same-address-conditional"
        graph.nodes[source]["role"] = "source"
        graph.nodes[entry]["role"] = "entry"
        graph.nodes[duplicate]["role"] = "duplicate"
        graph.edges[source, entry]["branch"] = "true"
        graph.edges[source, duplicate]["branch"] = "false"
        reverter = self._reverter(graph, entry)
        original_jump = source.statements[-1]
        assert isinstance(original_jump, ConditionalJump)
        original_jump.peephole_optimized = True
        original_tags = dict(original_jump.tags)

        result = reverter._uniquify_addrs(graph, entry)
        self.assertIsNotNone(result)
        assert result is not None

        result_source = next(node for node in result if node.addr == source.addr)
        result_entry = next(node for node in result if (node.addr, node.idx) == reverter.entry_node_addr)
        result_duplicate = next(node for node in result.successors(result_source) if node is not result_entry)
        result_jump = result_source.statements[-1]
        assert isinstance(result_jump, ConditionalJump)
        self.assertIsNot(result_jump, original_jump)
        self.assertIs(result_source.statements[0], prefix)
        self.assertTrue(prefix.peephole_optimized)
        self.assertTrue(original_jump.peephole_optimized)
        self.assertFalse(result_jump.peephole_optimized)

        self.assertEqual(result.graph, graph.graph)
        self.assertEqual(result.nodes[result_source], graph.nodes[source])
        self.assertEqual(result.edges[result_source, result_entry], graph.edges[source, entry])
        self.assertEqual(result.edges[result_source, result_duplicate], graph.edges[source, duplicate])
        self.assertEqual(
            self._conditional_targets(result_jump),
            ((result_entry.addr, result_entry.idx), (result_duplicate.addr, result_duplicate.idx)),
        )
        self.assertIs(source.statements[-1], original_jump)
        self.assertEqual(
            self._conditional_targets(original_jump),
            ((entry.addr, entry.idx), (duplicate.addr, duplicate.idx)),
        )
        self.assertEqual(original_jump.tags, original_tags)

    def test_uniquify_addrs_repairs_supported_edge_shapes(self):
        manager = Manager()
        with self.subTest(shape="indexed-self-loop"):
            entry = self._jump_block(manager, 0x100, 0x100, idx=7, target_idx=7)
            duplicate = self._jump_block(manager, 0x100, 0x200, idx=1)
            graph = nx.DiGraph([(entry, entry), (duplicate, Block(0x200, 1, statements=[]))])
            result = self._reverter(graph, entry)._uniquify_addrs(graph, entry)
            assert result is not None
            result_entry = next(node for node in result if (node.addr, node.idx) == (entry.addr, entry.idx))
            result_jump = result_entry.statements[-1]
            assert isinstance(result_jump, Jump)
            self.assertTrue(result.has_edge(result_entry, result_entry))
            self.assertEqual((result_jump.target.value, result_jump.target_idx), (entry.addr, entry.idx))

        with self.subTest(shape="one-broken-conditional-target"):
            source = self._conditional_block(manager, 0x10, 0x100, 0x999, true_target_idx=1, false_target_idx=9)
            successor_a = Block(0x100, 1, statements=[], idx=1)
            successor_b = Block(0x200, 1, statements=[], idx=2)
            graph = nx.DiGraph([(source, successor_a), (source, successor_b)])
            result = self._reverter(graph, source)._uniquify_addrs(graph, source)
            assert result is not None
            result_source = next(node for node in result if (node.addr, node.idx) == (source.addr, source.idx))
            result_jump = result_source.statements[-1]
            assert isinstance(result_jump, ConditionalJump)
            self.assertEqual(
                self._conditional_targets(result_jump), ((successor_a.addr, None), (successor_b.addr, None))
            )

        with self.subTest(shape="missing-terminator"):
            source = Block(0x10, 1, statements=[Label(manager.next_atom(), "source", ins_addr=0x10)])
            entry = Block(0x100, 1, statements=[], idx=7)
            graph = nx.DiGraph([(source, entry)])
            reverter = self._reverter(graph, entry)
            reverter.manager = manager
            reverter._func = Mock(project=Mock(arch=Mock(bits=64)))
            result = reverter._uniquify_addrs(graph, entry)
            assert result is not None
            result_source = next(node for node in result if node.addr == source.addr)
            result_jump = result_source.statements[-1]
            assert isinstance(result_jump, Jump)
            self.assertEqual((result_jump.target.value, result_jump.target_idx), (entry.addr, entry.idx))
            self.assertEqual(len(source.statements), 1)

    def test_generated_conditionals_include_target_indices(self):
        manager = Manager()
        start_a = self._jump_block(manager, 0x10, 0x100, target_idx=7)
        start_b = self._jump_block(manager, 0x20, 0x100, target_idx=1)
        successor_a = Block(0x100, 1, statements=[], idx=7)
        successor_b = Block(0x100, 1, statements=[], idx=1)
        original_graph = nx.DiGraph([(start_a, successor_a), (start_b, successor_b)])

        with self.subTest(path="single-node"):
            condition = self._conditional_block(manager, 0x80, 0, 0, idx=1)
            merged_node = Block(0x70, 1, statements=[])
            merge_graph = Mock(
                graph=nx.DiGraph(),
                original_split_blocks={},
            )
            merge_graph.graph.add_node(merged_node)
            merge_graph.create_conditionless_graph.return_value = {}
            reverter = self._reverter(original_graph, start_a)
            reverter._construct_best_condition_block_for_merge = Mock(return_value=(condition, start_a))
            with (
                patch.object(duplication_reverter_module, "longest_ail_graph_subseq", return_value=[]),
                patch.object(duplication_reverter_module, "AILMergeGraph", return_value=merge_graph),
            ):
                result = reverter.create_merged_subgraph((start_a, start_b), original_graph)

            generated = next(iter(result.graph.successors(merged_node))).statements[-1]
            assert isinstance(generated, ConditionalJump)
            self.assertEqual(
                self._conditional_targets(generated),
                ((successor_a.addr, successor_a.idx), (successor_b.addr, successor_b.idx)),
            )

        with self.subTest(path="merge-ends"):
            condition = self._conditional_block(manager, 0x90, 0, 0, idx=1)
            match_node = Block(0x60, 1, statements=[])
            merge_graph = AILMergeGraph(original_graph=original_graph)
            merge_graph.merge_blocks_to_originals[successor_a].add(successor_a)
            merge_graph.original_blocks[start_a] = [successor_a]
            merge_graph.add_edges_to_condition(condition, start_a, {match_node: [successor_a, successor_b]})

            generated = next(iter(merge_graph.graph.successors(match_node))).statements[-1]
            assert isinstance(generated, ConditionalJump)
            self.assertEqual(
                self._conditional_targets(generated),
                ((successor_a.addr, successor_a.idx), (successor_b.addr, successor_b.idx)),
            )

    def test_unsupported_edge_mapping_rolls_back(self):
        manager = Manager()
        cases = (
            ("ambiguous-address-only", (0x100, None), (0x100, None), ((0x100, 1), (0x100, 2))),
            ("no-edge-evidence", (0x500, 5), (0x600, 6), ((0x110, 1), (0x220, 2))),
            ("both-branches-identify-one-successor", (0x130, 1), (0x130, 1), ((0x130, 1), (0x230, 2))),
            ("more-than-two-successors", (0x140, 1), (0x240, 2), ((0x140, 1), (0x240, 2), (0x340, 3))),
        )

        for name, true_target, false_target, successor_pairs in cases:
            with self.subTest(name=name):
                entry = self._jump_block(manager, 0x10, 0x80)
                source = self._conditional_block(
                    manager,
                    0x80,
                    true_target[0],
                    false_target[0],
                    true_target_idx=true_target[1],
                    false_target_idx=false_target[1],
                )
                successors = [Block(addr, 1, statements=[], idx=idx) for addr, idx in successor_pairs]
                graph = nx.DiGraph([(entry, source), *((source, successor) for successor in successors)])
                graph.graph["case"] = name
                for edge_index, (src, dst) in enumerate(graph.edges):
                    graph.edges[src, dst]["edge_index"] = edge_index
                reverter = self._reverter(graph, entry)
                reverter._new_block_addrs.add(0xF00)
                self._assert_failed_finalization_is_transactional(reverter)

        with self.subTest(name="indirect-jump"):
            entry = self._jump_block(manager, 0x10, 0x80)
            source = Block(
                0x80,
                1,
                statements=[Jump(manager.next_atom(), Register(manager.next_atom(), 0, 64), ins_addr=0x80)],
            )
            successor = Block(0x100, 1, statements=[])
            reverter = self._reverter(nx.DiGraph([(entry, source), (source, successor)]), entry)
            self._assert_failed_finalization_is_transactional(reverter)

    def test_unresolvable_entry_rolls_back_without_uniquifying(self):
        manager = Manager()
        entry_a = self._jump_block(manager, 0x100, 0x280, target_idx=0xA1)
        entry_b = self._jump_block(manager, 0x100, 0x300)
        exit_a = Block(0x200, 1, statements=[], idx=0xA2)
        exit_b = Block(0x300, 1, statements=[])
        ambiguous_graph = nx.DiGraph([(entry_a, exit_a), (entry_b, exit_b)])
        self.assertEqual(len(ambiguous_graph), 4)

        other_entry = self._jump_block(manager, 0x500, 0x680, target_idx=0xB1)
        other_exit = Block(0x600, 1, statements=[], idx=0xB2)
        missing_graph = nx.DiGraph([(other_entry, other_exit)])
        missing_entry = Block(0x100, 1, statements=[])

        for name, graph, designated_entry in (
            ("missing", missing_graph, missing_entry),
            ("ambiguous", ambiguous_graph, entry_a),
        ):
            with self.subTest(name=name):
                reverter = self._reverter(graph, designated_entry)
                uniquify_addrs = Mock(wraps=reverter._uniquify_addrs)
                reverter._uniquify_addrs = uniquify_addrs
                self._assert_failed_finalization_is_transactional(reverter)
                uniquify_addrs.assert_not_called()

    def test_repeated_finalization_resolves_entry_in_current_graph(self):
        manager = Manager()
        entry = self._jump_block(manager, 0x100, 0x300)
        predecessor = self._jump_block(manager, 0x300, 0x100, target_idx=1)
        duplicate = self._jump_block(manager, 0x100, 0x400, idx=1)
        exit_node = Block(0x400, 1, statements=[])
        graph = nx.DiGraph([(entry, predecessor), (predecessor, duplicate), (duplicate, exit_node)])
        reverter = self._reverter(graph, entry)

        self.assertTrue(reverter._finalize_graph_after_reinsertion())
        first_graph = reverter.write_graph
        assert first_graph is not None
        first_result_entry = next(node for node in first_graph if (node.addr, node.idx) == reverter.entry_node_addr)

        copied_graph = copy_graph_and_nodes(first_graph)
        copied_entry = next(node for node in copied_graph if (node.addr, node.idx) == reverter.entry_node_addr)
        self.assertIsNot(copied_entry, first_result_entry)
        reverter.read_graph = copied_graph.copy()
        reverter.write_graph = copied_graph
        second_duplicate = Block(entry.addr, 1, statements=[], idx=2)
        reverter.write_graph.add_node(second_duplicate)

        self.assertTrue(reverter._finalize_graph_after_reinsertion())
        second_result_entry = next(
            node for node in reverter.write_graph if (node.addr, node.idx) == reverter.entry_node_addr
        )
        self.assertIsNot(second_result_entry, copied_entry)
        self.assertEqual(len({node.addr for node in reverter.write_graph}), len(reverter.write_graph))
        self.assertNotIn(entry.addr, {node.addr for node in reverter.write_graph if node is not second_result_entry})


if __name__ == "__main__":
    unittest.main()
