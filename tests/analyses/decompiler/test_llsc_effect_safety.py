from __future__ import annotations

import os
from typing import Any

import pytest

import angr
from angr import ailment
from angr.ailment.expression import DirtyExpression, VirtualVariableCategory
from angr.ailment.utils import (
    has_llsc_expression,
    has_store_conditional,
    is_llsc_expression,
    is_store_conditional_expression,
)
from angr.analyses.decompiler.block_io_finder import BlockIOFinder
from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.analyses.decompiler.block_walkers import HasCallExprWalker, HasCallNotification
from angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter import (
    DuplicationReverter,
)
from angr.analyses.decompiler.region_simplifiers.expr_folding import ExpressionCounter
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.knowledge_plugins.key_definitions.atoms import ConstantSrc, MemoryLocation
from tests.common import bin_location


def _project():
    binary = os.path.join(bin_location, "tests", "armel", "decompiler", "nuttx_O2_noinline")
    return angr.Project(binary, auto_load_libs=False)


def _store_conditional(idx: int, addr=None):
    addr = addr if addr is not None else ailment.Expr.Const(idx + 1, 0x2000, 64)
    data = ailment.Expr.Const(idx + 2, 0x42, 64)
    return DirtyExpression(
        idx,
        "store_conditional_le",
        [addr, data],
        mfx="Ifx_Write",
        maddr=addr,
        msize=8,
        bits=1,
    )


def _dirty_expressions(block: ailment.Block) -> list[DirtyExpression]:
    return [
        stmt.src
        for stmt in block.statements
        if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, DirtyExpression)
    ]


def test_llsc_effect_classification_is_atomic_specific():
    store_conditional = _store_conditional(0)
    generic_dirty_write = DirtyExpression(
        3,
        "unrelated_helper",
        [],
        mfx="Ifx_Write",
        bits=1,
    )
    mismatched_llsc = DirtyExpression(
        4,
        "store_conditional_le",
        [],
        mfx="Ifx_Read",
        bits=1,
    )
    nested = ailment.Expr.MultiStatementExpression(
        5,
        [ailment.Stmt.Assignment(6, ailment.Expr.Tmp(7, 0, 1), store_conditional)],
        ailment.Expr.Const(8, 0, 1),
    )

    assert is_llsc_expression(store_conditional)
    assert is_store_conditional_expression(store_conditional)
    assert has_llsc_expression(nested)
    assert has_store_conditional(nested)
    assert not is_llsc_expression(generic_dirty_write)
    assert not is_store_conditional_expression(generic_dirty_write)
    assert not is_llsc_expression(mismatched_llsc)


def test_unused_store_conditional_survives_block_simplification():
    project = _project()
    manager = ailment.Manager()
    ail_block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                0,
                ailment.Expr.Tmp(1, 0, 1),
                _store_conditional(2),
                ins_addr=0x1000,
            )
        ],
    )

    assert [expr.callee for expr in _dirty_expressions(ail_block)] == ["store_conditional_le"]
    simplified = BlockSimplifier(project, ail_block, manager, peephole_optimizations=[]).result_block
    assert simplified is not None
    assert [expr.callee for expr in _dirty_expressions(simplified)] == ["store_conditional_le"]


def test_store_conditional_is_a_motion_and_region_folding_barrier():
    project = _project()
    atomic_stmt = ailment.Stmt.Assignment(
        0,
        ailment.Expr.Tmp(1, 0, 1),
        _store_conditional(2),
        ins_addr=0x1000,
    )
    ordinary_stmt = ailment.Stmt.Assignment(
        5,
        ailment.Expr.Register(6, 16, 64),
        ailment.Expr.Const(7, 1, 64),
        ins_addr=0x1001,
    )
    block = ailment.Block(0x1000, 2, statements=[ordinary_stmt, atomic_stmt])
    io_finder = BlockIOFinder(block, project)

    assert io_finder.side_effects_at == {1}
    assert not io_finder.can_swap(ordinary_stmt, block, 1)
    mover = object.__new__(DuplicationReverter)
    assert not mover.stmt_can_move_to(ordinary_stmt, block, 1, io_finder=io_finder)
    assert not mover.stmt_can_move_to(atomic_stmt, block, 0, io_finder=io_finder)

    nested_atomic = ailment.Expr.MultiStatementExpression(
        8,
        [atomic_stmt],
        ailment.Expr.Const(9, 0, 1),
    )
    nested_block = ailment.Block(
        0x1800,
        1,
        statements=[ailment.Stmt.Assignment(10, ailment.Expr.Tmp(11, 1, 1), nested_atomic), ordinary_stmt],
    )
    assert BlockIOFinder(nested_block, project).side_effects_at == {0}

    atomic_vvar = ailment.Expr.VirtualVariable(12, 1, 1, VirtualVariableCategory.REGISTER, oident=16)
    pure_vvar = ailment.Expr.VirtualVariable(13, 2, 64, VirtualVariableCategory.REGISTER, oident=24)
    folding_block = ailment.Block(
        0x2000,
        1,
        statements=[
            ailment.Stmt.Assignment(14, atomic_vvar, _store_conditional(15)),
            ailment.Stmt.Assignment(18, pure_vvar, DirtyExpression(19, "unsupported_arithmetic", [], bits=64)),
            ailment.Stmt.Return(
                20,
                [
                    ailment.Expr.VirtualVariable(21, atomic_vvar.varid, 1, VirtualVariableCategory.REGISTER, oident=16),
                    ailment.Expr.VirtualVariable(22, pure_vvar.varid, 64, VirtualVariableCategory.REGISTER, oident=24),
                ],
            ),
        ],
        idx=0,
    )
    counter = ExpressionCounter(SequenceNode(folding_block.addr, nodes=[folding_block]))
    assert atomic_vvar.varid not in counter.assignments
    assert pure_vvar.varid in counter.assignments


def _load_linked(idx: int, addr=None, guard=None):
    addr = addr if addr is not None else ailment.Expr.Const(idx + 1, 0x2000, 64)
    return DirtyExpression(
        idx,
        "load_linked_le",
        [addr],
        guard=guard,
        mfx="Ifx_Read",
        maddr=addr,
        msize=8,
        bits=64,
    )


def test_load_linked_reads_its_address_and_its_guard():
    project = _project()
    addr = ailment.Expr.Const(1, 0x2000, 64)
    guard = ailment.Expr.Const(2, 7, 64)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                0,
                ailment.Expr.Tmp(3, 0, 64),
                _load_linked(4, addr=addr, guard=guard),
                ins_addr=0x1000,
            )
        ],
    )
    io_finder = BlockIOFinder(block, project)

    # the load is an atomic side effect even though it writes no memory
    assert io_finder.side_effects_at == {0}
    # its address is dereferenced and is an input, not an output
    location = MemoryLocation(0x2000, 8)
    assert location in io_finder.derefed_at[0]
    assert location in io_finder.inputs_by_stmt[0]
    assert location not in io_finder.outputs_by_stmt[0]
    # the guard is read too
    assert ConstantSrc(7, 8) in io_finder.inputs_by_stmt[0]


def test_llsc_expression_reads_as_a_call_to_the_block_simplifier():
    walker = HasCallExprWalker()
    atomic = ailment.Stmt.Assignment(0, ailment.Expr.Tmp(1, 0, 64), _load_linked(2), ins_addr=0x1000)
    ordinary = ailment.Stmt.Assignment(
        3,
        ailment.Expr.Tmp(4, 1, 64),
        DirtyExpression(5, "unsupported_arithmetic", [], bits=64),
        ins_addr=0x1001,
    )

    with pytest.raises(HasCallNotification):
        walker.walk_statement(atomic)
    walker.walk_statement(ordinary)


def test_llsc_detection_walks_statements_and_rejects_other_objects():
    atomic = ailment.Stmt.Assignment(0, ailment.Expr.Tmp(1, 0, 1), _store_conditional(2), ins_addr=0x1000)
    ordinary = ailment.Stmt.Assignment(
        3,
        ailment.Expr.Tmp(4, 1, 64),
        DirtyExpression(5, "unsupported_arithmetic", [], bits=64),
        ins_addr=0x1001,
    )

    assert has_llsc_expression(atomic)
    assert has_store_conditional(atomic)
    assert not has_llsc_expression(ordinary)
    assert not has_store_conditional(ordinary)
    not_an_ail_object: Any = 0x1000
    with pytest.raises(TypeError):
        has_llsc_expression(not_an_ail_object)


def test_an_atomic_statement_blocks_movement_across_it_in_both_directions():
    project = _project()
    first = ailment.Stmt.Assignment(
        0,
        ailment.Expr.Register(1, 16, 64),
        ailment.Expr.Const(2, 1, 64),
        ins_addr=0x1000,
    )
    atomic = ailment.Stmt.Assignment(
        3,
        ailment.Expr.Tmp(4, 0, 1),
        _store_conditional(5),
        ins_addr=0x1001,
    )
    last = ailment.Stmt.Assignment(
        8,
        ailment.Expr.Register(9, 24, 64),
        ailment.Expr.Const(10, 2, 64),
        ins_addr=0x1002,
    )
    block = ailment.Block(0x1000, 3, statements=[first, atomic, last])
    io_finder = BlockIOFinder(block, project)
    assert io_finder.side_effects_at == {1}

    mover = object.__new__(DuplicationReverter)
    # neither ordinary statement is itself a side effect, so the barrier is the
    # atomic statement they would have to cross
    assert not mover.stmt_can_move_to(first, block, 2, io_finder=io_finder)
    assert not mover.stmt_can_move_to(last, block, 0, io_finder=io_finder)
