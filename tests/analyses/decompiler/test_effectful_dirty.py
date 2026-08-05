from __future__ import annotations

import angr
from angr import ailment
from angr.ailment.expression import DirtyExpression, VirtualVariableCategory
from angr.analyses.decompiler.block_io_finder import BlockIOFinder
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter import (
    DuplicationReverter,
)
from angr.analyses.decompiler.region_simplifiers.expr_folding import ExpressionCounter
from angr.analyses.decompiler.structurer_nodes import SequenceNode


def _project():
    return angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)


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
    dirty_expressions = []
    for stmt in block.statements:
        if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, DirtyExpression):
            dirty_expressions.append(stmt.src)
    return dirty_expressions


def test_unused_store_conditional_survives_block_simplification_and_full_decompilation():
    # AArch64 `stxr wzr, x1, [x3]; ret`: the status result is intentionally discarded,
    # but the conditional store itself must still execute exactly once.
    project = angr.load_shellcode(bytes.fromhex("617c1fc8c0035fd6"), "AARCH64", load_address=0x1000, start_offset=0)
    manager = ailment.Manager(arch=project.arch)
    ail_block = ailment.IRSBConverter.convert(project.factory.block(0x1000, size=8).vex, manager)

    dirty_expressions = _dirty_expressions(ail_block)
    assert len(dirty_expressions) == 1
    assert dirty_expressions[0].callee == "store_conditional_le"

    simplified = project.analyses.AILBlockSimplifier(ail_block, manager, peephole_optimizations=[]).result_block
    assert [expr.callee for expr in _dirty_expressions(simplified)].count("store_conditional_le") == 1

    cfg = project.analyses.CFGFast(normalize=True, function_starts=[0x1000], fail_fast=True)
    function = cfg.functions[0x1000]
    decompilation = project.analyses[Decompiler].prep(fail_fast=True)(function, cfg=cfg)
    assert decompilation.codegen is not None and decompilation.codegen.text is not None
    assert decompilation.codegen.text.count("store_conditional_le") == 1


def test_pure_dirty_expression_remains_dead_assignment_eliminatable():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    pure = DirtyExpression(0, "unsupported_arithmetic", [], bits=64)
    effectful = _store_conditional(1)
    guest_state_effect = DirtyExpression(4, "helper_guest_state", [], mfx="Ifx_None", bits=64)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(5, ailment.Expr.Tmp(6, 0, 64), pure, ins_addr=0x1000),
            ailment.Stmt.Assignment(7, ailment.Expr.Tmp(8, 1, 64), guest_state_effect, ins_addr=0x1001),
            ailment.Stmt.Assignment(9, ailment.Expr.Tmp(10, 2, 1), effectful, ins_addr=0x1002),
            ailment.Stmt.Return(11, [], ins_addr=0x1003),
        ],
    )

    simplified = project.analyses.AILBlockSimplifier(block, manager, peephole_optimizations=[]).result_block
    callees = [expr.callee for expr in _dirty_expressions(simplified)]
    assert "unsupported_arithmetic" not in callees
    assert callees.count("helper_guest_state") == 1
    assert callees.count("store_conditional_le") == 1


def test_spropagator_does_not_duplicate_effectful_dirty_tmp_or_vvar_definitions():
    project = _project()
    manager = ailment.Manager(arch=project.arch)

    tmp = ailment.Expr.Tmp(0, 0, 1)
    tmp_use_0 = ailment.Expr.Tmp(1, 0, 1)
    tmp_use_1 = ailment.Expr.Tmp(2, 0, 1)
    tmp_block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(3, tmp, _store_conditional(4), ins_addr=0x1000),
            ailment.Stmt.Assignment(7, ailment.Expr.Register(8, 16, 1), tmp_use_0, ins_addr=0x1001),
            ailment.Stmt.Assignment(9, ailment.Expr.Register(10, 17, 1), tmp_use_1, ins_addr=0x1002),
        ],
        idx=0,
    )
    tmp_prop = project.analyses.SPropagator(tmp_block, ail_manager=manager)
    assert not any(
        tmp_use in replacements for replacements in tmp_prop.replacements.values() for tmp_use in (tmp_use_0, tmp_use_1)
    )

    vvar_def = ailment.Expr.VirtualVariable(11, 1, 1, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_0 = ailment.Expr.VirtualVariable(12, 1, 1, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_1 = ailment.Expr.VirtualVariable(13, 1, 1, VirtualVariableCategory.REGISTER, oident=16)
    vvar_block = ailment.Block(
        0x2000,
        1,
        statements=[
            ailment.Stmt.Assignment(14, vvar_def, _store_conditional(15), ins_addr=0x2000),
            ailment.Stmt.ConditionalJump(
                18,
                vvar_use_0,
                ailment.Expr.Const(19, 0x2000, 64),
                ailment.Expr.Const(20, 0x3000, 64),
                true_target_idx=0,
                ins_addr=0x2001,
            ),
            ailment.Stmt.Jump(21, vvar_use_1, ins_addr=0x2002),
        ],
        idx=0,
    )
    vvar_prop = project.analyses.SPropagator(vvar_block, ail_manager=manager)
    assert not any(
        vvar_use in replacements
        for replacements in vvar_prop.replacements.values()
        for vvar_use in (vvar_use_0, vvar_use_1)
    )
    assert vvar_def.varid not in vvar_prop.dead_vvar_ids


def test_spropagator_does_not_move_load_across_dirty_memory_write():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    load_tmp = ailment.Expr.Tmp(0, 0, 32)
    load_use = ailment.Expr.Tmp(1, 0, 32)
    addr = ailment.Expr.Const(2, 0x3000, 64)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                3,
                load_tmp,
                ailment.Expr.Load(4, addr, 4, "Iend_LE"),
                ins_addr=0x1000,
            ),
            ailment.Stmt.Assignment(
                5,
                ailment.Expr.Tmp(6, 1, 1),
                _store_conditional(7, addr=addr),
                ins_addr=0x1001,
            ),
            ailment.Stmt.Assignment(
                10,
                ailment.Expr.Register(11, 16, 32),
                load_use,
                ins_addr=0x1002,
            ),
        ],
    )

    propagator = project.analyses.SPropagator(block, ail_manager=manager)
    assert not any(load_use in replacements for replacements in propagator.replacements.values())


def test_effectful_dirty_expression_is_a_motion_and_region_folding_barrier():
    project = _project()
    effectful_stmt = ailment.Stmt.Assignment(
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
    block = ailment.Block(0x1000, 2, statements=[ordinary_stmt, effectful_stmt])
    io_finder = BlockIOFinder(block, project)

    assert io_finder.side_effects_at == {1}
    assert not io_finder.can_swap(ordinary_stmt, block, 1)
    mover = object.__new__(DuplicationReverter)
    assert not mover.stmt_can_move_to(ordinary_stmt, block, 1, io_finder=io_finder)
    assert not mover.stmt_can_move_to(effectful_stmt, block, 0, io_finder=io_finder)

    nested_effect = ailment.Expr.MultiStatementExpression(
        8,
        [effectful_stmt],
        ailment.Expr.Const(9, 0, 1),
    )
    nested_block = ailment.Block(
        0x1800,
        1,
        statements=[
            ailment.Stmt.Assignment(
                10,
                ailment.Expr.Tmp(11, 1, 1),
                nested_effect,
            ),
            ordinary_stmt,
        ],
    )
    assert BlockIOFinder(nested_block, project).side_effects_at == {0}

    effectful_vvar = ailment.Expr.VirtualVariable(12, 1, 1, VirtualVariableCategory.REGISTER, oident=16)
    pure_vvar = ailment.Expr.VirtualVariable(13, 2, 64, VirtualVariableCategory.REGISTER, oident=24)
    folding_block = ailment.Block(
        0x2000,
        1,
        statements=[
            ailment.Stmt.Assignment(14, effectful_vvar, _store_conditional(15)),
            ailment.Stmt.Assignment(
                18,
                pure_vvar,
                DirtyExpression(19, "unsupported_arithmetic", [], bits=64),
            ),
            ailment.Stmt.Return(
                20,
                [
                    ailment.Expr.VirtualVariable(
                        21, effectful_vvar.varid, 1, VirtualVariableCategory.REGISTER, oident=16
                    ),
                    ailment.Expr.VirtualVariable(22, pure_vvar.varid, 64, VirtualVariableCategory.REGISTER, oident=24),
                ],
            ),
        ],
        idx=0,
    )
    counter = ExpressionCounter(SequenceNode(folding_block.addr, nodes=[folding_block]))
    assert effectful_vvar.varid not in counter.assignments
    assert pure_vvar.varid in counter.assignments


def test_classic_reaching_definitions_accepts_dirty_expression_metadata():
    project = _project()
    addr = ailment.Expr.Register(0, 16, 64)
    guard = ailment.Expr.Register(1, 24, 1)
    dirty = DirtyExpression(
        2,
        "store_conditional_le",
        [addr, ailment.Expr.Const(3, 1, 64)],
        guard=guard,
        mfx="Ifx_Write",
        maddr=addr,
        msize=8,
        bits=1,
    )
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(4, ailment.Expr.Tmp(5, 0, 1), dirty, ins_addr=0x1000),
            ailment.Stmt.Return(6, [], ins_addr=0x1001),
        ],
    )

    project.analyses.ReachingDefinitions(subject=block, track_tmps=True)
