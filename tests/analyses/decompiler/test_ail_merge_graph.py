from __future__ import annotations

from angr.ailment import Block
from angr.analyses.decompiler.optimization_passes.duplication_reverter.ail_merge_graph import (
    AILBlockSplit,
    AILMergeGraph,
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
