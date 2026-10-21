#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Block
from angr.ailment.expression import Const
from angr.ailment.statement import ConditionalJump, Jump, Label
from angr.analyses.decompiler.redundant_label_remover import RedundantLabelRemover
from angr.analyses.decompiler.structurer_nodes import SequenceNode


def _label(addr: int) -> Label:
    return Label(0, f"LABEL_{addr:x}", ins_addr=addr, block_idx=0)


def _shared_copy(block: Block) -> Block:
    # what a structuring probe works on: a new block that shares the statement objects (see copy_graph)
    return Block(block.addr, block.original_size, statements=list(block.statements), idx=block.idx)


class TestRedundantLabelRemover(unittest.TestCase):
    def test_retargeting_a_jump_does_not_touch_the_shared_statement(self):
        # LABEL_400104 directly follows LABEL_400100, so jumps to it are retargeted to LABEL_400100
        labels = Block(0x400100, 0, statements=[_label(0x400100), _label(0x400104)])
        jump = Block(0x400200, 4, statements=[Jump(0, Const(1, 0x400104, 32), ins_addr=0x400200)])
        cond = Block(
            0x400300,
            4,
            statements=[
                ConditionalJump(0, Const(2, 1, 1), Const(3, 0x400104, 32), Const(4, 0x400108, 32), ins_addr=0x400300)
            ],
        )
        jump_copy, cond_copy = _shared_copy(jump), _shared_copy(cond)
        tree = SequenceNode(0x400100, nodes=[labels, jump_copy, cond_copy])

        RedundantLabelRemover(tree, {(0x400104, 0), (0x400108, 0)})

        assert jump_copy.statements[-1].target.value == 0x400100
        assert cond_copy.statements[0].true_target.value == 0x400100
        assert cond_copy.statements[0].false_target.value == 0x400108
        # the blocks the copies were made from still jump to the original label
        assert jump.statements[-1].target.value == 0x400104
        assert cond.statements[0].true_target.value == 0x400104


if __name__ == "__main__":
    unittest.main()
