#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Block
from angr.ailment.expression import Const, Register
from angr.ailment.statement import Assignment, Jump
from angr.analyses.decompiler.clinic import Clinic


def _jump(target, ins_addr=0x400100):
    return Jump(0, Const(1, target, 32), ins_addr=ins_addr)


class TestITETriangleRelistedBlock(unittest.TestCase):
    """
    _create_triangle_for_ite_expression truncates the head block at the ITE statement and leaves the end
    block to carry whatever the original block ended with. An end block with no statements cannot carry
    it, so the rewrite has to be declined rather than performed.
    """

    def test_a_statementless_end_block_refuses_the_rewrite(self):
        # graph recovery emits a zero-size block for a fall-through that no instruction backs
        patched = Block(0x400100, 4, statements=[_jump(0x400200)])
        relifted = Block(0x400104, 0, statements=[])

        assert Clinic._remove_redundant_jump_blocks_repatch_relifted_block(patched, relifted) is False

    def test_a_relifted_block_that_carries_the_jump_is_repatched(self):
        patched = Block(0x400100, 4, statements=[_jump(0x400200)])
        relifted = Block(0x400100, 4, statements=[_jump(0x400104)])

        assert Clinic._remove_redundant_jump_blocks_repatch_relifted_block(patched, relifted) is True
        assert relifted.statements[-1].likes(_jump(0x400200))

    def test_a_head_that_does_not_end_in_a_jump_is_accepted_unchanged(self):
        patched = Block(0x400100, 4, statements=[Assignment(0, Register(1, 8, 32), Const(2, 1, 32), ins_addr=0x400100)])
        relifted = Block(0x400100, 4, statements=[_jump(0x400104)])

        assert Clinic._remove_redundant_jump_blocks_repatch_relifted_block(patched, relifted) is True
        assert relifted.statements[-1].likes(_jump(0x400104))


if __name__ == "__main__":
    unittest.main()
