from __future__ import annotations

import unittest
from typing import cast

import networkx as nx

from angr.ailment import Block, Const
from angr.ailment.statement import ConditionalJump, Jump, Label, Return
from angr.analyses.decompiler.optimization_passes.duplication_reverter.ail_merge_graph import AILMergeGraph


class TestAILMergeGraphSplitChain(unittest.TestCase):
    """Tests replacement chains and cyclic graph shapes."""

    def test_split_chain_uses_live_predecessor_copy(self):
        target = Block(0x4010, 4, statements=[Return(0, [])])
        predecessor = Block(0x4000, 4, statements=[Jump(0, Const(0, target.addr, 64))])
        graph = nx.DiGraph([(predecessor, target)])

        split_target = Block(0x5010, 4, statements=[Return(0, [])])
        split_predecessor = Block(0x5000, 4, statements=[Jump(0, Const(0, split_target.addr, 64))])

        cloned_graph, updated_blocks = AILMergeGraph.clone_graph_replace_splits(
            graph, {target: split_target, predecessor: split_predecessor}
        )

        self.assertEqual(set(cloned_graph.nodes), {split_predecessor, split_target})
        self.assertEqual(set(cloned_graph.edges), {(split_predecessor, split_target)})
        self.assertEqual(updated_blocks, {})

    def test_fanout_replacements_resolve_to_live_blocks(self):
        first_target = Block(0x4010, 4, statements=[Return(0, [])])
        second_target = Block(0x4020, 4, statements=[Return(0, [])])
        condition = Const(0, 1, 1)
        split_source = Block(
            0x4000,
            4,
            statements=[
                ConditionalJump(
                    0,
                    condition,
                    Const(1, first_target.addr, 64),
                    Const(2, second_target.addr, 64),
                )
            ],
        )
        unsplit_source = Block(
            0x4100,
            4,
            statements=[
                ConditionalJump(
                    0,
                    condition,
                    Const(1, first_target.addr, 64),
                    Const(2, second_target.addr, 64),
                )
            ],
        )
        graph = nx.DiGraph(
            [
                (split_source, first_target),
                (split_source, second_target),
                (unsplit_source, first_target),
                (unsplit_source, second_target),
            ]
        )

        split_first_target = Block(0x5010, 4, statements=[Return(0, [])])
        split_second_target = Block(0x5020, 4, statements=[Return(0, [])])
        split_source_replacement = Block(
            0x5000,
            4,
            statements=[
                ConditionalJump(
                    0,
                    condition,
                    Const(1, split_first_target.addr, 64),
                    Const(2, split_second_target.addr, 64),
                )
            ],
        )

        cloned_graph, updated_blocks = AILMergeGraph.clone_graph_replace_splits(
            graph,
            {
                first_target: split_first_target,
                second_target: split_second_target,
                split_source: split_source_replacement,
            },
        )

        live_unsplit_source = updated_blocks[unsplit_source]
        self.assertEqual(
            set(cloned_graph.nodes),
            {split_source_replacement, live_unsplit_source, split_first_target, split_second_target},
        )
        self.assertEqual(
            set(cloned_graph.edges),
            {
                (split_source_replacement, split_first_target),
                (split_source_replacement, split_second_target),
                (live_unsplit_source, split_first_target),
                (live_unsplit_source, split_second_target),
            },
        )
        self.assertTrue(all(replacement is live_unsplit_source for replacement in updated_blocks.values()))
        self.assertTrue(all(replacement in cloned_graph for replacement in updated_blocks.values()))
        jump = cast(ConditionalJump, live_unsplit_source.statements[-1])
        self.assertIsInstance(jump, ConditionalJump)
        self.assertEqual(
            {jump.true_target.value, jump.false_target.value},
            {split_first_target.addr, split_second_target.addr},
        )

    def test_split_self_loop(self):
        loop = Block(0x6000, 4, statements=[Jump(0, Const(0, 0x6000, 64))])
        graph = nx.DiGraph([(loop, loop)])
        split_loop = Block(0x7000, 4, statements=[Jump(0, Const(0, loop.addr, 64))])

        cloned_graph, updated_blocks = AILMergeGraph.clone_graph_replace_splits(graph, {loop: split_loop})

        self.assertEqual(set(cloned_graph.nodes), {split_loop})
        self.assertEqual(set(cloned_graph.edges), {(split_loop, split_loop)})
        jump = cast(Jump, split_loop.statements[-1])
        self.assertEqual(jump.target.value, split_loop.addr)
        self.assertEqual(updated_blocks, {})

    def test_split_two_node_loop_uses_live_successor_copy(self):
        first = Block(0x6000, 4, statements=[Jump(0, Const(0, 0x6010, 64))])
        second = Block(0x6010, 4, statements=[Jump(0, Const(0, 0x6000, 64))])
        graph = nx.DiGraph([(first, second), (second, first)])
        split_second = Block(0x7010, 4, statements=[Jump(0, Const(0, first.addr, 64))])

        cloned_graph, updated_blocks = AILMergeGraph.clone_graph_replace_splits(graph, {second: split_second})

        live_first = updated_blocks[first]
        self.assertEqual(set(cloned_graph.nodes), {live_first, split_second})
        self.assertEqual(set(cloned_graph.edges), {(live_first, split_second), (split_second, live_first)})
        self.assertTrue(all(replacement in cloned_graph for replacement in updated_blocks.values()))

    def test_equal_predecessor_copy_resolves_by_identity(self):
        target = Block(0x8010, 8, statements=[Label(0, "target"), Return(1, [])])
        predecessor = Block(0x8000, 4, statements=[Jump(0, Const(0, target.addr, 64))])
        graph = nx.DiGraph([(predecessor, target)])
        split_target = Block(target.addr, 4, statements=[Return(1, [])])

        cloned_graph, updated_blocks = AILMergeGraph.clone_graph_replace_splits(graph, {target: split_target})

        live_predecessor = updated_blocks[predecessor]
        self.assertEqual(set(cloned_graph.nodes), {live_predecessor, split_target})
        self.assertEqual(set(cloned_graph.edges), {(live_predecessor, split_target)})
        self.assertTrue(all(replacement in cloned_graph for replacement in updated_blocks.values()))


if __name__ == "__main__":
    unittest.main()
