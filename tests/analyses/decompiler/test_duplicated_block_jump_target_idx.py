#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.utils import update_jump_target_idx
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDuplicatedBlockJumpTargetIdx(unittest.TestCase):
    """
    A pass that copies a block under a new index and redirects a predecessor's edge to the copy must also update the
    index named by the predecessor's jump, or later passes see a jump whose target is not among the successors.
    """

    def test_update_jump_target_idx(self):
        m = Manager()
        jump = Jump(m.next_atom(), Const(m.next_atom(), 0x1000, 64), 0, ins_addr=0x10)
        block = Block(0x10, 2, statements=[jump])
        assert not update_jump_target_idx(block, 0x2000, 0, 3)
        assert not update_jump_target_idx(block, 0x1000, 1, 3)
        assert update_jump_target_idx(block, 0x1000, 0, 3)
        assert block.statements[-1].target_idx == 3

        cjump = ConditionalJump(
            m.next_atom(),
            Const(m.next_atom(), 1, 1),
            Const(m.next_atom(), 0x1000, 64),
            Const(m.next_atom(), 0x1000, 64),
            true_target_idx=0,
            false_target_idx=2,
            ins_addr=0x20,
        )
        block = Block(0x20, 2, statements=[cjump])
        assert update_jump_target_idx(block, 0x1000, None, 5)
        assert block.statements[-1].true_target_idx == 5
        assert block.statements[-1].false_target_idx == 5

    def test_tar_maybe_recoverable_default_case_duplication(self):
        # case 2 of the lowered switch shares its body with the jump table's default node; SwitchDefaultCaseDuplicator
        # copies the default node for that predecessor and must retarget the predecessor's jump to the copy
        bin_path = os.path.join(test_location, "x86_64", "decbench_tar_O0_stripped")
        func_addr, size = 0x419950, 0x27E
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            normalize=True, regions=[(func_addr, func_addr + size)], function_starts=[func_addr]
        )
        logger = logging.getLogger("angr.analyses.decompiler.optimization_passes.lowered_switch_simplifier")
        with self.assertNoLogs(logger, level=logging.WARNING):
            dec = proj.analyses.Decompiler(func_addr, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert dec.structuring_failures == []
        assert "case 2:" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
