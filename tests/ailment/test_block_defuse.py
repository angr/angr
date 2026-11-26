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
from angr.ailment.statement import Assignment, Label, Return, SideEffectStatement, Statement, Store
from angr.rustylib.ailment import StatementList, UsesDefs, block_defuse_is_cached, block_tmp_defs_uses
from angr.utils.ssa import get_tmp_deflocs, get_tmp_uselocs, get_uses_defs, get_vvar_deflocs


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
            stmts[0] = Return(61, [])

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

    def test_unchanged_statements_keep_the_memo(self):
        b0 = make_blocks()[0]
        get_vvar_deflocs([b0])
        # writing back the statement that is there, or a rebuilt list of the same statements
        b0.statements[0] = b0.statements[0]
        assert block_defuse_is_cached(b0) is True
        b0.statements = list(b0.statements)
        assert block_defuse_is_cached(b0) is True
        assert block_defuse_is_cached(b0.copy(statements=b0.statements[:])) is True
        b0.statements = b0.statements[1:]
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

    def test_phi_stmt_counts(self):
        b0, b1 = make_blocks()
        assert (b0.phi_stmt_count, b0.non_phi_stmt_count) == (0, 6)
        assert (b1.phi_stmt_count, b1.non_phi_stmt_count) == (1, 2)
        # phis follow the leading labels
        phi = b1.statements[0]
        b1.statements[0:0] = [Label(90, "l0"), Label(91, "l1"), phi]
        assert (b1.phi_stmt_count, b1.non_phi_stmt_count) == (2, 4)
        b1.statements = [stmt for stmt in b1.statements if stmt is not phi]
        assert (b1.phi_stmt_count, b1.non_phi_stmt_count) == (0, 4)
        assert Block(0x2000, 4).phi_stmt_count == 0

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

    def test_uses_defs_queries_match_the_merged_containers(self):
        blocks = make_blocks()
        phis: dict = {}
        defs, uses, tmp_defs, tmp_uses = get_uses_defs(blocks, phi_vvars=phis)
        ud = UsesDefs(blocks)

        ud_phis: dict = {}
        ud_defs = ud.vvar_defs(ud_phis)
        assert list(ud_defs.items()) == list(defs.items())
        assert ud_phis == phis

        all_uses = ud.all_vvar_uses()
        assert list(all_uses.items()) == list(uses.items())
        for varid, sites in uses.items():
            assert ud.has_vvar_uses(varid) is True
            assert ud.vvar_uses(varid) == sites
            assert ud.vvar_uses(varid) is ud.vvar_uses(varid)
        assert ud.has_vvar_uses(12345) is False
        assert ud.vvar_uses(12345) == []

        expected = [
            (block_loc, tmp_defs[block_loc][tmp], sites)
            for block_loc, by_tmp in tmp_uses.items()
            for tmp, sites in by_tmp.items()
            if tmp in tmp_defs.get(block_loc, {})
        ]
        assert expected
        assert ud.tmp_defs_uses() == expected

    def test_uses_defs_register_use_ids(self):
        ud = UsesDefs(make_blocks())
        # vv(_, n) is the register at offset 8 * n
        assert ud.register_use_ids([16, 40], set()) == [2, 5]
        assert ud.register_use_ids([16], {9, 777}) == [2, 9]
        assert ud.register_use_ids([], set()) == []

    def test_uses_defs_argless_call_stmts(self):
        call = Call(70, Const(71, 0x2000, 64))
        block = Block(
            0x3000,
            8,
            statements=[
                SideEffectStatement(1, call),
                SideEffectStatement(2, Call(72, Const(73, 0x2000, 64), args=[])),
                Assignment(3, vv(74, 1), call),
                Assignment(4, vv(75, 2), Const(76, 1, 64)),
                Return(5, [call]),
            ],
        )
        assert UsesDefs([*make_blocks(), block]).argless_call_stmts() == [((0x3000, 0), i) for i in (0, 2, 4)]

    def test_uses_defs_block_reg_defs(self):
        blocks = make_blocks()
        blocks[0].statements.append(Assignment(80, vv(81, 11, 32), Const(82, 1, 32)))
        blocks[0].statements.append(Assignment(83, vv(84, 12), Const(85, 1, 64)))
        ud = UsesDefs(blocks)
        # registers 8 and 16 (vvars 1, 2) share base 0: the later definition counts. width is part of the key
        result = ud.block_reg_defs(lambda reg_offset, size: 0 if reg_offset in (8, 16) else reg_offset)
        assert list(result) == [(0x1000, 0), (0x1010, 0)]
        b0 = result[(0x1000, 0)]
        assert b0[(0, 8)] == 2
        assert b0[(88, 4)] == 11
        assert b0[(96, 8)] == 12
        assert result[(0x1010, 0)] == {(72, 8): 9, (80, 8): 10}

    def test_uses_defs_is_a_snapshot(self):
        blocks = make_blocks()
        ud = UsesDefs(blocks)
        before = list(ud.vvar_defs())
        blocks[0].statements = blocks[0].statements[1:]
        assert list(ud.vvar_defs()) == before
        assert list(UsesDefs(blocks).vvar_defs()) != before

    def test_block_tmp_defs_uses(self):
        for block in make_blocks():
            block_loc = (block.addr, block.idx)
            defs = get_tmp_deflocs([block]).get(block_loc, {})
            uses = get_tmp_uselocs([block]).get(block_loc, {})
            result = block_tmp_defs_uses(block)
            if not defs:
                assert result is None
                continue
            assert result == (
                {tmp.tmp_idx: stmt_idx for tmp, stmt_idx in defs.items()},
                {tmp.tmp_idx: {stmt_idx for _, stmt_idx in sites} for tmp, sites in uses.items()},
            )
        assert block_tmp_defs_uses(make_blocks()[0]) == ({0: 2}, {0: {3}})


if __name__ == "__main__":
    unittest.main()
