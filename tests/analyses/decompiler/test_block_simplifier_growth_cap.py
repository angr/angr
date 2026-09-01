#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.block_simplifier import (
    AILCodeLocation,
    BlockSimplifier,
    _statement_text_size,
)

LEAVES = 16


def _wide(manager, leaves):
    """
    A balanced Add tree: wide, but only log2(leaves) deep.

    Building it left-leaning instead would grow depth with width, and the existing depth cap would
    reject it -- which is exactly the shape the depth cap *cannot* see, and the reason a separate
    size bound is needed.
    """
    level = [Const(manager.next_atom(), i + 1, 64) for i in range(leaves)]
    while len(level) > 1:
        level = [
            BinaryOp(manager.next_atom(), "Add", [level[i], level[i + 1]], False, bits=64)
            if i + 1 < len(level)
            else level[i]
            for i in range(0, len(level), 2)
        ]
    return level[0]


class TestGrowthCap(unittest.TestCase):
    """One statement absorbing many replacements must not grow without bound."""

    def _case(self):
        manager = Manager(arch=None)
        regs = [Register(manager.next_atom(), 8 * (i + 2), 64) for i in range(LEAVES)]
        level = list(regs)
        while len(level) > 1:
            level = [
                BinaryOp(manager.next_atom(), "Add", [level[i], level[i + 1]], False, bits=64)
                if i + 1 < len(level)
                else level[i]
                for i in range(0, len(level), 2)
            ]
        src = level[0]
        stmt = Assignment(manager.next_atom(), Register(manager.next_atom(), 16, 64), src, ins_addr=0x1000)
        block = Block(0x1000, 1, statements=[stmt])
        # every register in the chain is replaced by a wide expression, all into this one statement
        replacements = {
            AILCodeLocation(0x1000, None, 0): {reg: _wide(manager, 32) for reg in regs},
        }
        return block, replacements, manager

    def test_uncapped_growth_is_large(self):
        block, replacements, manager = self._case()
        _, new_block = BlockSimplifier.replace_and_build(block, replacements, manager, max_stmt_size=None)
        assert _statement_text_size(new_block.statements[0]) > 4000

    def test_the_cap_bounds_the_statement(self):
        block, replacements, manager = self._case()
        cap = 2000
        changed, new_block = BlockSimplifier.replace_and_build(block, replacements, manager, max_stmt_size=cap)
        assert changed, "the cap must not block every replacement, only runaway growth"
        grown = _statement_text_size(new_block.statements[0])
        # the estimate is per-replacement, so the result can overshoot by one grafted expression
        assert grown < cap * 3, f"statement grew to {grown} under a cap of {cap}"

    def test_a_capped_statement_still_reflects_early_replacements(self):
        block, replacements, manager = self._case()
        _, new_block = BlockSimplifier.replace_and_build(block, replacements, manager, max_stmt_size=2000)
        # something was substituted: the statement is no longer the bare register chain
        assert _statement_text_size(new_block.statements[0]) > _statement_text_size(block.statements[0])


class TestStatementTextSize(unittest.TestCase):
    def test_size_grows_with_the_expression(self):
        manager = Manager(arch=None)
        small = Assignment(
            manager.next_atom(), Register(manager.next_atom(), 16, 64), _wide(manager, 2), ins_addr=0x1000
        )
        big = Assignment(
            manager.next_atom(), Register(manager.next_atom(), 16, 64), _wide(manager, 128), ins_addr=0x1000
        )
        assert _statement_text_size(big) > _statement_text_size(small) * 5

    def test_depth_does_not_track_width(self):
        # The reason a depth cap cannot bound this: width explodes while depth crawls.
        manager = Manager(arch=None)
        narrow, wide = _wide(manager, 2), _wide(manager, 256)
        assert _statement_text_size(wide) > 20 * _statement_text_size(narrow)


if __name__ == "__main__":
    unittest.main()
