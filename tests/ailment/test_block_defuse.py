# pylint:disable=missing-class-docstring,no-self-use
"""Per-block def/use lists memoized on the Rust Block (angr.utils.ssa over rustylib.ailment.collect_uses_defs)."""

from __future__ import annotations

import unittest
from typing import Any

from angr.ailment import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    MultiStatementExpression,
    Phi,
    Tmp,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Return, SideEffectStatement, Statement, Store
from angr.rustylib.ailment import StatementList, block_defuse_is_cached
from angr.utils.ssa import get_uses_defs, get_vvar_deflocs


def vv(idx: int, varid: int, bits: int = 64) -> VirtualVariable:
    return VirtualVariable(idx, varid, bits, VirtualVariableCategory.REGISTER, oident=8 * varid)


def make_blocks() -> list[Block]:
    """Two blocks exercising every def/use source: plain defs, a phi, a Reference extra def, call clobber defs,
    a Call ret_expr def, a MultiStatementExpression (nested uses are not recorded), tmps, and a WeakAssignment-free
    Store."""
    ins: dict[str, Any] = {"ins_addr": 0x1000}
    b0 = Block(
        0x1000,
        16,
        statements=[
            Assignment(1, vv(10, 1), Const(11, 5, 64), **ins),
            Assignment(2, vv(12, 2), BinaryOp(13, "Add", [vv(14, 1), Const(15, 1, 64)], False), **ins),
            Assignment(3, Tmp(16, 0, 64), vv(17, 2), **ins),
            Store(4, vv(18, 2), Tmp(19, 0, 64), 8, "Iend_LE", **ins),
            # extra def: vvar_3 is first seen as the operand of a tagged Reference
            Assignment(
                5,
                vv(20, 4),
                UnaryOp(21, "Reference", vv(22, 3), extra_def=True),
                extra_defs=[3],
                **ins,
            ),
            # a call that clobbers registers (varid, reg_offset, bits) and returns into vvar_5
            SideEffectStatement(
                6,
                Call(23, Const(24, 0x2000, 64), args=[vv(25, 4), vv(26, 3)]),
                ret_expr=vv(27, 5),
                clobber_defs=[6, 24, 64, 7, 32, 64],
                **ins,
            ),
        ],
    )
    nested = [Assignment(30, Tmp(31, 1, 64), vv(32, 5)), Assignment(33, vv(34, 8), Tmp(35, 1, 64))]
    b1 = Block(
        0x1010,
        16,
        statements=[
            Assignment(
                7, vv(40, 9), Phi(41, 64, [((0x1000, 0), vv(42, 2)), ((0x1010, 0), vv(43, 9)), ((0x1020, 0), None)])
            ),
            Assignment(
                8, vv(44, 10), MultiStatementExpression(45, nested, BinaryOp(46, "Sub", [vv(47, 9), vv(48, 5)], False))
            ),
            Return(9, [vv(49, 10)]),
        ],
    )
    return [b0, b1]


class TestBlockDefUse(unittest.TestCase):
    def test_replaced_statement_invalidates_that_block_only(self):
        b0 = make_blocks()[0]
        b1 = b0.copy()
        get_vvar_deflocs([b0, b1])
        assert block_defuse_is_cached(b1) is True
        # statements are immutable: a change is a new statement written into one block
        first = b1.statements[0]
        assert isinstance(first, Assignment)
        b1.statements[0] = first.copy_with(dst=vv(70, 11))
        assert block_defuse_is_cached(b0) is True
        assert block_defuse_is_cached(b1) is False
        assert 11 in get_vvar_deflocs([b1])
        assert 11 not in get_vvar_deflocs([b0])

    def test_every_list_mutation_invalidates(self):
        b0 = make_blocks()[0]
        stmts = b0.statements
        extra = Return(60, [])

        def setitem():
            stmts[0] = extra

        def set_slice():
            stmts[0:1] = [extra, extra]

        def delitem():
            del stmts[0]

        def iadd():
            nonlocal stmts
            stmts += [extra]

        def assign():
            b0.statements = [extra]

        for mutate in (
            lambda: stmts.append(extra),
            lambda: stmts.insert(0, extra),
            lambda: stmts.extend([extra]),
            setitem,
            set_slice,
            delitem,
            iadd,
            lambda: stmts.pop(),
            lambda: stmts.remove(extra),
            lambda: stmts.reverse(),
            lambda: stmts.sort(key=lambda stmt: stmt.idx),
            lambda: stmts.clear(),
            assign,
        ):
            get_vvar_deflocs([b0])
            assert block_defuse_is_cached(b0) is True
            mutate()
            assert block_defuse_is_cached(b0) is False

    def test_statements_is_a_list_owned_by_the_block(self):
        given: list[Statement] = [Return(60, [])]
        block = Block(0x1000, 4, statements=given)
        assert isinstance(block.statements, StatementList)
        assert block.statements == given
        # the block keeps its own list; a StatementList is shared as is
        assert block.statements is not given
        assert Block(0x2000, 4, statements=block.statements).statements is block.statements
        assert type(block.statements[:]) is list
        assert block.copy().statements is not block.statements

    def test_merged_containers_are_fresh(self):
        blocks = make_blocks()
        defs_a, uses_a, _, _ = get_uses_defs(blocks)
        count = len(uses_a[1])
        uses_a[1].append(uses_a[1][0])
        del defs_a[1]
        defs_b, uses_b, _, _ = get_uses_defs(blocks)
        assert len(uses_b[1]) == count
        assert 1 in defs_b
        assert uses_b[12345] == []  # defaultdict shape preserved


if __name__ == "__main__":
    unittest.main()
