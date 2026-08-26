from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import cast

from angr.ailment import Block, Const
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter import (
    DuplicationReverter,
)


class TestDuplicationReverterTags(unittest.TestCase):
    """Tests statement-tag ownership in synthesized duplication-reverter blocks."""

    def test_synthesized_condition_does_not_inherit_extra_defs(self):
        common_condition = Block(
            0x1000,
            1,
            statements=[
                Jump(
                    0,
                    Const(0, 0x2000, 64),
                    ins_addr=0x1000,
                    vex_stmt_idx=7,
                    extra_defs=[41, 42],
                )
            ],
            idx=0,
        )
        true_block = Block(0x2000, 1)
        condition = Const(1, 1, 1)
        atom_ids = iter((2, 3))
        reverter = cast(
            DuplicationReverter,
            SimpleNamespace(
                shared_common_conditional_dom=lambda blocks, graph: common_condition,
                collect_conditions_between_nodes=lambda graph, common, blocks: {true_block: condition},
                boolean_operators_in_condition=lambda expr: 0,
                max_guarding_conditions=4,
                candidate_blacklist=set(),
                manager=SimpleNamespace(next_atom=lambda: next(atom_ids)),
                project=SimpleNamespace(arch=SimpleNamespace(bits=64)),
            ),
        )

        result, selected = DuplicationReverter._construct_best_condition_block_for_merge(  # pylint: disable=protected-access
            reverter, (true_block,), object()
        )

        statement = cast(ConditionalJump, result.statements[0])
        self.assertIs(selected, true_block)
        self.assertNotIn("extra_defs", statement.tags)
        self.assertEqual(statement.tags["ins_addr"], 0x1000)
        self.assertEqual(statement.tags["vex_stmt_idx"], 7)
        self.assertEqual(common_condition.statements[0].tags["extra_defs"], [41, 42])


if __name__ == "__main__":
    unittest.main()
