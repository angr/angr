from __future__ import annotations

import unittest
from typing import cast

from angr.ailment import Block, Const
from angr.ailment.statement import ConditionalJump, Return
from angr.analyses.decompiler.optimization_passes.duplication_reverter.ail_merge_graph import AILMergeGraph


class TestDuplicationReverterJumpTargets(unittest.TestCase):
    """Tests generated jump targets during duplication reversal."""

    def test_add_edges_replaces_placeholder_target_addresses(self):
        start0 = Block(0x1000, 1, statements=[Return(0, [])])
        start1 = Block(0x2000, 1, statements=[Return(0, [])])
        original0 = Block(0x1100, 1, statements=[Return(0, [])])
        original1 = Block(0x2100, 1, statements=[Return(0, [])])
        match = Block(0x3000, 1, statements=[Return(0, [])])
        end0 = Block(0x4000, 1, statements=[Return(0, [])], idx=1)
        end1 = Block(0x4100, 1, statements=[Return(0, [])], idx=2)
        conditional = Block(
            0x5000,
            1,
            statements=[
                ConditionalJump(
                    0,
                    Const(0, 1, 1, condition_tag="condition"),
                    Const(1, 0, 64, target_tag="true"),
                    Const(2, 0, 64, target_tag="false"),
                    stmt_tag="statement",
                )
            ],
            idx=1,
        )

        merge = AILMergeGraph()
        merge.starts = [start0, start1]
        merge.original_blocks = {start0: [original0], start1: [original1]}
        merge.merge_blocks_to_originals = {end0: {original0}, end1: {original1}}
        merge.graph.add_node(match)

        merge.add_edges_to_condition(conditional, start0, {match: [end0, end1]})

        generated = next(iter(merge.graph.successors(match)))
        stmt = cast(ConditionalJump, generated.statements[-1])
        self.assertEqual(stmt.true_target.value, end0.addr)
        self.assertEqual(stmt.false_target.value, end1.addr)
        self.assertIsNone(stmt.true_target_idx)
        self.assertIsNone(stmt.false_target_idx)
        self.assertEqual(stmt.tags["stmt_tag"], "statement")
        self.assertEqual(stmt.condition.tags["condition_tag"], "condition")
        self.assertEqual(stmt.true_target.tags["target_tag"], "true")
        self.assertEqual(stmt.false_target.tags["target_tag"], "false")
        self.assertEqual(set(merge.graph.successors(generated)), {end0, end1})


if __name__ == "__main__":
    unittest.main()
