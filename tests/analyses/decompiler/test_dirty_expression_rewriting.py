# pylint: disable=protected-access
from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest

from angr.ailment import Block
from angr.ailment.expression import Const, DirtyExpression, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import DirtyStatement
from angr.analyses.decompiler.dephication.rewriting_engine import SimEngineDephiRewriting
from angr.analyses.decompiler.ssailification.rewriting_engine import SimEngineSSARewriting


@pytest.mark.parametrize("engine_cls", (SimEngineSSARewriting, SimEngineDephiRewriting))
@pytest.mark.parametrize("rewritten_fields", ({"maddr"}, {"operand"}, {"guard", "maddr"}))
def test_dirty_rewriting_preserves_unchanged_fields(engine_cls, rewritten_fields):
    operand = Const(0, 1, 64)
    guard = Const(1, 1, 1)
    maddr = Const(2, 0x4000, 64)
    dirty = DirtyExpression(
        3,
        "helper",
        [operand],
        guard=guard,
        mfx="Ifx_Modify",
        maddr=maddr,
        msize=4,
        bits=32,
        ins_addr=0x400000,
    )
    replacements = {
        operand: Const(4, 2, 64),
        guard: Const(5, 0, 1),
        maddr: Const(6, 0x5000, 64),
    }

    engine = object.__new__(engine_cls)
    engine._expr = lambda expr: (
        replacements[expr]
        if expr in replacements
        and {
            operand: "operand",
            guard: "guard",
            maddr: "maddr",
        }[expr]
        in rewritten_fields
        else None
    )

    rewritten = engine._handle_expr_DirtyExpression(dirty)

    assert rewritten is not None
    expected_operand = replacements[operand] if "operand" in rewritten_fields else operand
    expected_guard = replacements[guard] if "guard" in rewritten_fields else guard
    expected_maddr = replacements[maddr] if "maddr" in rewritten_fields else maddr
    assert rewritten.operands[0].likes(expected_operand)
    assert rewritten.guard is not None and rewritten.guard.likes(expected_guard)
    assert rewritten.maddr is not None and rewritten.maddr.likes(expected_maddr)
    assert rewritten.idx == dirty.idx
    assert rewritten.callee == dirty.callee
    assert rewritten.mfx == dirty.mfx
    assert rewritten.msize == dirty.msize
    assert rewritten.bits == dirty.bits
    assert rewritten.tags == dirty.tags


def test_dephication_rewrites_dirty_memory_address_through_engine():
    operand = VirtualVariable(0, 10, 64, VirtualVariableCategory.REGISTER, oident=16)
    unchanged_operand = VirtualVariable(1, 11, 64, VirtualVariableCategory.REGISTER, oident=24)
    guard = VirtualVariable(2, 12, 1, VirtualVariableCategory.TMP, oident=0)
    maddr = VirtualVariable(3, 14, 64, VirtualVariableCategory.REGISTER, oident=32)
    dirty = DirtyExpression(
        4,
        "helper",
        [operand, unchanged_operand],
        guard=guard,
        mfx="Ifx_Modify",
        maddr=maddr,
        msize=8,
        bits=64,
        ins_addr=0x400000,
    )
    block = Block(0x400000, 1, statements=[DirtyStatement(5, dirty)])

    engine = SimEngineDephiRewriting(
        SimpleNamespace(arch=archinfo.ArchAMD64()),
        {
            operand.varid: 110,
            maddr.varid: 114,
        },
    )
    engine.process(None, block=block)

    assert engine.out_block is not None
    new_stmt = engine.out_block.statements[0]
    assert isinstance(new_stmt, DirtyStatement)
    new_dirty = new_stmt.dirty
    assert isinstance(new_dirty, DirtyExpression)
    assert [operand_.varid for operand_ in new_dirty.operands] == [110, unchanged_operand.varid]
    assert isinstance(new_dirty.guard, VirtualVariable)
    assert new_dirty.guard.varid == guard.varid
    assert isinstance(new_dirty.maddr, VirtualVariable)
    assert new_dirty.maddr.varid == 114
    assert new_dirty.callee == dirty.callee
    assert new_dirty.mfx == dirty.mfx
    assert new_dirty.msize == dirty.msize
    assert new_dirty.bits == dirty.bits
    assert new_dirty.tags == dirty.tags
