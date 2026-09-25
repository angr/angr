from __future__ import annotations

# pylint: disable=protected-access
import unittest

import networkx as nx

from angr.ailment import Block, Const
from angr.ailment.statement import Jump, Label, Return
from angr.analyses.decompiler.optimization_passes.duplication_reverter.ail_merge_graph import (
    AILBlockSplit,
    AILMergeGraph,
)


class TestAILMergeGraph(unittest.TestCase):
    """Tests metadata updates performed while constructing an AIL merge graph."""

    def test_split_replacement_migrates_equal_predecessor_metadata_by_identity(self):
        before = Block(0x3FF0)
        split_original = Block(0x4010, 8, statements=[Label(0, "target"), Return(1, [])])
        predecessor = Block(0x4000, 4, statements=[Jump(1, Const(1, split_original.addr, 64))], idx=1)
        after = Block(0x4020)
        graph = nx.DiGraph([(predecessor, split_original)])

        split_replacement = Block(split_original.addr, 4, statements=[Return(1, [])])
        before_splits = [AILBlockSplit(original=before)]
        tracked_split = AILBlockSplit(original=split_original, up_split=predecessor)
        tracked_splits = [tracked_split]
        after_splits = [AILBlockSplit(original=after)]
        original_split_blocks = {
            before: before_splits,
            predecessor: tracked_splits,
            after: after_splits,
        }
        before_blocks = [before]
        tracked_blocks = [predecessor, split_original]
        after_blocks = [after]
        original_blocks = {
            before: before_blocks,
            predecessor: tracked_blocks,
            after: after_blocks,
        }
        merge_graph = AILMergeGraph(
            original_graph=graph,
            original_blocks=original_blocks,
            original_split_blocks=original_split_blocks,
        )

        cloned_graph, updates = merge_graph.clone_graph_replace_splits(graph, {split_original: split_replacement})

        self.assertEqual(len(updates), 1)
        copied_predecessor, updated_predecessor = next(iter(updates.items()))
        self.assertEqual(copied_predecessor, predecessor)
        self.assertIsNot(copied_predecessor, predecessor)
        self.assertEqual(updated_predecessor, predecessor)
        self.assertIsNot(updated_predecessor, predecessor)
        self.assertIsNot(updated_predecessor, copied_predecessor)
        self.assertTrue(any(node is updated_predecessor for node in cloned_graph))

        merge_graph._update_all_split_refs(updates)

        self.assertIs(merge_graph.original_split_blocks, original_split_blocks)
        self.assertIs(merge_graph.original_blocks, original_blocks)
        for mapping, values in (
            (original_split_blocks, (before_splits, tracked_splits, after_splits)),
            (original_blocks, (before_blocks, tracked_blocks, after_blocks)),
        ):
            keys = list(mapping)
            self.assertEqual(len(keys), 3)
            self.assertIs(keys[0], before)
            self.assertIs(keys[1], updated_predecessor)
            self.assertIs(keys[2], after)
            self.assertTrue(all(actual is expected for actual, expected in zip(mapping.values(), values)))
            self.assertFalse(any(key is predecessor for key in keys))

        self.assertIs(tracked_split.up_split, updated_predecessor)
