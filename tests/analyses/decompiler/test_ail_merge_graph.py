from __future__ import annotations

import networkx as nx

from angr.ailment import Assignment, Block, Const, Register
from angr.analyses.decompiler.optimization_passes.duplication_reverter.ail_merge_graph import (
    AILBlockSplit,
    AILMergeGraph,
)
from angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter import (
    DuplicationReverter,
)


def test_update_all_split_refs_with_equal_replacement_block():
    original = Block(0x4000, 4, idx=1)
    replacement = original.copy()
    assert replacement is not original
    assert replacement == original

    split = AILBlockSplit(original=original, up_split=original)
    split_entries = [split]
    original_entries = [original]
    merge_graph = AILMergeGraph(
        original_blocks={original: original_entries},
        original_split_blocks={original: split_entries},
    )

    merge_graph._update_all_split_refs({original: replacement})  # pylint: disable=protected-access

    assert next(iter(merge_graph.original_split_blocks)) is replacement
    assert merge_graph.original_split_blocks[replacement] is split_entries
    assert next(iter(merge_graph.original_blocks)) is replacement
    assert merge_graph.original_blocks[replacement] is original_entries
    assert split.up_split is replacement


def test_reinsert_merged_candidate_rolls_back_ambiguous_fallthrough_predecessor():
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

    reverter = DuplicationReverter.__new__(DuplicationReverter)
    reverter.read_graph = original_graph.copy()
    reverter.write_graph = original_graph.copy()

    success = reverter._reinsert_merged_candidate(  # pylint: disable=protected-access
        merge_graph, (candidate_0, candidate_1)
    )

    assert not success
    assert reverter.write_graph is not reverter.read_graph
    assert set(reverter.write_graph.nodes) == set(original_graph.nodes)
    assert set(reverter.write_graph.edges) == set(original_graph.edges)
