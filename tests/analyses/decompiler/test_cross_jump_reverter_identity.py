#!/usr/bin/env python3
# pylint:disable=protected-access,super-init-not-called
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from itertools import count
from types import SimpleNamespace
from typing import Any, cast

import networkx

from angr.ailment import Block, Manager
from angr.ailment.expression import Const
from angr.ailment.statement import Jump, Label
from angr.analyses.decompiler.goto_manager import Goto, GotoManager
from angr.analyses.decompiler.optimization_passes.cross_jump_reverter import CrossJumpReverter


def _jump_block(addr, idx, target_addr, target_idx, ins_addr):
    return Block(
        addr,
        4,
        statements=[Jump(0, Const(1, target_addr, 64), target_idx=target_idx, ins_addr=ins_addr)],
        idx=idx,
    )


def _labeled_block(addr, idx, label):
    return Block(addr, 4, statements=[Label(0, label, ins_addr=addr, block_idx=idx)], idx=idx)


class _CrossJumpHarness(CrossJumpReverter):
    def __init__(self, graph, gotos):
        self.out_graph = graph
        self._goto_manager = GotoManager(SimpleNamespace(addr=0), set(gotos))
        self.manager = Manager()
        self.node_idx = count()
        self._max_call_dup = 1
        self._processed_targets = set()


class TestCrossJumpReverterIdentity(unittest.TestCase):  # pylint:disable=missing-class-docstring
    def test_shifted_source_copies_only_exact_immediate_destination(self):
        source = _jump_block(0x1000, 7, 0x2000, 2, 0x1003)
        sibling = _labeled_block(0x2000, 1, "sibling")
        target = _labeled_block(0x2000, 2, "exact")
        sibling_sink = Block(0x3000, 4, idx=0)
        target_sink = Block(0x4000, 4, idx=0)
        graph = networkx.DiGraph()
        graph.add_edge(source, sibling)
        graph.add_edge(source, target)
        graph.add_edge(sibling, sibling_sink)
        graph.add_edge(target, target_sink)
        goto = Goto(0x1003, 0x2000, src_idx=None, dst_idx=2, src_ins_addr=0x1003)

        self.assertTrue(_CrossJumpHarness(graph, {goto})._analyze())

        self.assertIn(sibling, graph)
        self.assertNotIn(target, graph)
        copied = next(node for node in graph.successors(source) if node is not sibling)
        self.assertEqual((copied.addr, copied.idx), (0x2000, 0))
        self.assertEqual(cast(Any, copied.statements[0]).name, "exact")

    def test_processed_target_is_not_retried_on_later_analysis(self):
        source = _jump_block(0x1000, 0, 0x2000, 2, 0x1003)
        target = _labeled_block(0x2000, 2, "target")
        keeper = Block(0x3000, 4, idx=0)
        sink = Block(0x4000, 4, idx=0)
        graph = networkx.DiGraph()
        graph.add_edge(source, target)
        graph.add_edge(keeper, target)
        graph.add_edge(target, sink)
        goto = Goto(0x1000, 0x2000, src_idx=0, dst_idx=2, src_ins_addr=0x1003)
        harness = _CrossJumpHarness(graph, {goto})

        self.assertTrue(harness._analyze())
        self.assertIn(target, graph)
        self.assertEqual(harness._processed_targets, {(0x2000, 2)})

        later_source = _jump_block(0x1100, 1, 0x2000, 2, 0x1103)
        later_goto = Goto(0x1100, 0x2000, src_idx=1, dst_idx=2, src_ins_addr=0x1103)
        graph.add_edge(later_source, target)
        cast(GotoManager, harness._goto_manager).gotos.add(later_goto)
        nodes_before = set(graph)
        edges_before = set(graph.edges)

        self.assertFalse(harness._analyze())
        self.assertEqual(set(graph), nodes_before)
        self.assertEqual(set(graph.edges), edges_before)

    def test_same_target_sources_are_copied_in_one_batch(self):
        source_a = _jump_block(0x1000, 0, 0x2000, 2, 0x1003)
        source_b = _jump_block(0x1100, 1, 0x2000, 2, 0x1103)
        target = _labeled_block(0x2000, 2, "target")
        sink = Block(0x3000, 4, idx=0)
        graph = networkx.DiGraph()
        graph.add_edge(source_a, target)
        graph.add_edge(source_b, target)
        graph.add_edge(target, sink)
        gotos = {
            Goto(0x1000, 0x2000, src_idx=0, dst_idx=2, src_ins_addr=0x1003),
            Goto(0x1100, 0x2000, src_idx=1, dst_idx=2, src_ins_addr=0x1103),
        }
        harness = _CrossJumpHarness(graph, gotos)

        self.assertTrue(harness._analyze())

        self.assertNotIn(target, graph)
        copies = [next(graph.successors(source)) for source in (source_a, source_b)]
        self.assertEqual({(copy.addr, copy.idx) for copy in copies}, {(0x2000, 0), (0x2000, 1)})
        self.assertTrue(all(cast(Any, copy.statements[0]).name == "target" for copy in copies))
        self.assertEqual(harness._processed_targets, {(0x2000, 2)})

    def test_later_distinct_exact_target_keys_are_still_copied(self):
        source = _jump_block(0x1000, 0, 0x2000, 2, 0x1003)
        target = _labeled_block(0x2000, 2, "initial")
        sink = Block(0x3000, 4, idx=0)
        graph = networkx.DiGraph()
        graph.add_edge(source, target)
        graph.add_edge(target, sink)
        goto = Goto(0x1000, 0x2000, src_idx=0, dst_idx=2, src_ins_addr=0x1003)
        harness = _CrossJumpHarness(graph, {goto})
        self.assertTrue(harness._analyze())

        distinct_source = _jump_block(0x4000, 0, 0x5000, 4, 0x4003)
        distinct_target = _labeled_block(0x5000, 4, "distinct")
        distinct_sink = Block(0x6000, 4, idx=0)
        sibling_source = _jump_block(0x7000, 0, 0x2000, 3, 0x7003)
        sibling_target = _labeled_block(0x2000, 3, "sibling")
        sibling_sink = Block(0x8000, 4, idx=0)
        graph.add_edge(distinct_source, distinct_target)
        graph.add_edge(distinct_target, distinct_sink)
        graph.add_edge(sibling_source, sibling_target)
        graph.add_edge(sibling_target, sibling_sink)
        cast(GotoManager, harness._goto_manager).gotos.update(
            {
                Goto(0x4000, 0x5000, src_idx=0, dst_idx=4, src_ins_addr=0x4003),
                Goto(0x7000, 0x2000, src_idx=0, dst_idx=3, src_ins_addr=0x7003),
            }
        )

        self.assertTrue(harness._analyze())

        self.assertNotIn(distinct_target, graph)
        self.assertNotIn(sibling_target, graph)
        distinct_copy = next(graph.successors(distinct_source))
        sibling_copy = next(graph.successors(sibling_source))
        self.assertEqual(cast(Any, distinct_copy.statements[0]).name, "distinct")
        self.assertEqual(cast(Any, sibling_copy.statements[0]).name, "sibling")
        self.assertEqual(harness._processed_targets, {(0x2000, 2), (0x2000, 3), (0x5000, 4)})

    def test_ambiguous_shifted_source_or_exact_non_successor_does_not_mutate(self):
        ambiguous_a = _jump_block(0x1100, 1, 0x2000, 2, 0x1003)
        ambiguous_b = _jump_block(0x1200, 2, 0x2000, 2, 0x1003)
        ambiguous_target = _labeled_block(0x2000, 2, "target")
        ambiguous_sink = Block(0x3000, 4, idx=0)
        ambiguous_graph = networkx.DiGraph()
        ambiguous_graph.add_edge(ambiguous_a, ambiguous_target)
        ambiguous_graph.add_edge(ambiguous_b, ambiguous_target)
        ambiguous_graph.add_edge(ambiguous_target, ambiguous_sink)
        ambiguous_goto = Goto(0x1003, 0x2000, src_idx=None, dst_idx=2, src_ins_addr=0x1003)

        exact_source = _jump_block(0x5000, 0, 0x6000, 2, 0x5003)
        non_target_sibling = _labeled_block(0x6000, 1, "sibling")
        exact_target = _labeled_block(0x6000, 2, "target")
        sibling_sink = Block(0x7000, 4, idx=0)
        target_sink = Block(0x8000, 4, idx=0)
        non_successor_graph = networkx.DiGraph()
        non_successor_graph.add_edge(exact_source, non_target_sibling)
        non_successor_graph.add_edge(non_target_sibling, sibling_sink)
        non_successor_graph.add_edge(exact_target, target_sink)
        non_successor_goto = Goto(0x5000, 0x6000, src_idx=0, dst_idx=2, src_ins_addr=0x5003)

        cases = (
            ("ambiguous shifted source", ambiguous_graph, ambiguous_goto),
            ("exact destination is not a successor", non_successor_graph, non_successor_goto),
        )
        for name, graph, goto in cases:
            with self.subTest(name=name):
                nodes_before = set(graph)
                edges_before = set(graph.edges)

                self.assertFalse(_CrossJumpHarness(graph, {goto})._analyze())

                self.assertEqual(set(graph), nodes_before)
                self.assertEqual(set(graph.edges), edges_before)


if __name__ == "__main__":
    unittest.main()
