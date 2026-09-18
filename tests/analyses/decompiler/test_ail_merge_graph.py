from __future__ import annotations

import os.path
import unittest

import networkx as nx

from angr.ailment import Assignment, Block, Const, Manager, Register
from angr.ailment.statement import Return
from angr.analyses.decompiler.optimization_passes.duplication_reverter.ail_merge_graph import (
    AILBlockSplit,
    AILMergeGraph,
)
from angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter import (
    DuplicationReverter,
)
from tests.common import bin_location, load_project_with_scoped_cfg


class TestAILMergeGraph(unittest.TestCase):
    """Check metadata replacement and rollback of a rejected merged graph."""

    def test_update_all_split_refs_with_equal_replacement_block(self):
        original = Block(0x4000, 4, idx=1)
        replacement = original.copy()
        self.assertIsNot(replacement, original)
        self.assertEqual(replacement, original)

        split = AILBlockSplit(original=original, up_split=original)
        split_entries = [split]
        original_entries = [original]
        merge_graph = AILMergeGraph(
            original_blocks={original: original_entries},
            original_split_blocks={original: split_entries},
        )

        merge_graph._update_all_split_refs({original: replacement})  # pylint: disable=protected-access

        self.assertIs(next(iter(merge_graph.original_split_blocks)), replacement)
        self.assertIs(merge_graph.original_split_blocks[replacement], split_entries)
        self.assertIs(next(iter(merge_graph.original_blocks)), replacement)
        self.assertIs(merge_graph.original_blocks[replacement], original_entries)
        self.assertIs(split.up_split, replacement)

    def test_reinsert_merged_candidate_rolls_back_ambiguous_fallthrough_predecessor(self):
        proj, cfg = load_project_with_scoped_cfg(os.path.join(bin_location, "tests", "x86_64", "true"), 0x401D30)
        func = cfg.functions[0x401D30]
        manager = Manager()
        entry_graph = nx.DiGraph()
        entry_graph.add_node(Block(func.addr, 0, statements=[Return(0, [])]))
        ri = proj.analyses.RegionIdentifier(func, graph=entry_graph, ail_manager=manager)
        reverter = DuplicationReverter(func, manager, graph=entry_graph, region_identifier=ri)

        predecessor = Block(
            0x1000,
            4,
            statements=[Assignment(0, Register(1, 0, 64), Const(2, 1, 64))],
        )
        candidate_0 = Block(0x2000, 4, statements=[Assignment(3, Register(4, 8, 64), Const(5, 2, 64))])
        candidate_1 = Block(0x3000, 4, statements=[Assignment(6, Register(7, 16, 64), Const(8, 3, 64))])
        merged = Block(0x4000, 4, statements=[Assignment(9, Register(10, 24, 64), Const(11, 4, 64))])

        original_graph = nx.DiGraph([(predecessor, predecessor), (predecessor, candidate_0)])
        original_graph.add_node(candidate_1)

        merged_subgraph = nx.DiGraph()
        merged_subgraph.add_node(merged)
        merge_graph = AILMergeGraph(
            graph=merged_subgraph,
            original_blocks={candidate_0: [candidate_0], candidate_1: [candidate_1]},
        )
        merge_graph.merge_blocks_to_originals[merged] = {candidate_0, candidate_1}

        reverter.read_graph = original_graph.copy()
        reverter.write_graph = original_graph.copy()

        success = reverter._reinsert_merged_candidate(  # pylint: disable=protected-access
            merge_graph, (candidate_0, candidate_1)
        )

        self.assertFalse(success)
        self.assertIsNot(reverter.write_graph, reverter.read_graph)
        self.assertEqual(set(reverter.write_graph.nodes), set(original_graph.nodes))
        self.assertEqual(set(reverter.write_graph.edges), set(original_graph.edges))


if __name__ == "__main__":
    unittest.main()
