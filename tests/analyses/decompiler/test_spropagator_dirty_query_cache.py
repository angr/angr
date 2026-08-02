from __future__ import annotations

from collections import defaultdict

import networkx
import pytest

import angr
import angr.analyses.s_propagator as spropagator_module
from angr import ailment
from angr.ailment.expression import DirtyExpression, VirtualVariable, VirtualVariableCategory
from angr.analyses.s_propagator import SPropagator


def _project():
    return angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)


def _dirty(idx: int, mfx: str | None, *, maddr=None, bits: int = 64) -> DirtyExpression:
    return DirtyExpression(
        idx,
        f"helper_{idx}",
        [],
        mfx=mfx,
        maddr=maddr,
        msize=8 if maddr is not None else None,
        bits=bits,
    )


def _function_propagator(project, block: ailment.Block, manager: ailment.Manager) -> SPropagator:
    function = project.kb.functions.function(addr=block.addr, create=True)
    assert function is not None
    graph = networkx.DiGraph()
    graph.add_node(block)
    return SPropagator(project, subject=function, func_graph=graph, ail_manager=manager)


def _has_replacement(propagator: SPropagator, expressions) -> bool:
    return any(expr in replacements for replacements in propagator.replacements.values() for expr in expressions)


def _effect_source_switch_block(mfx: str | None):
    vvar_def = VirtualVariable(0, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_0 = VirtualVariable(1, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_1 = VirtualVariable(2, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    block = ailment.Block(
        0x2000,
        1,
        statements=[
            ailment.Stmt.Assignment(3, vvar_def, _dirty(4, mfx), ins_addr=0x2000),
            ailment.Stmt.ConditionalJump(
                5,
                vvar_use_0,
                ailment.Expr.Const(6, 0x2000, 64),
                ailment.Expr.Const(7, 0x3000, 64),
                true_target_idx=0,
                ins_addr=0x2001,
            ),
            ailment.Stmt.Jump(8, vvar_use_1, ins_addr=0x2002),
        ],
        idx=0,
    )
    return block, vvar_def, (vvar_use_0, vvar_use_1)


def _global_load_block(mfx: str):
    addr = ailment.Expr.Const(0, 0x3000, 64)
    vvar_def = VirtualVariable(1, 1, 32, VirtualVariableCategory.REGISTER, oident=16)
    vvar_uses = [VirtualVariable(idx + 2, 1, 32, VirtualVariableCategory.REGISTER, oident=16) for idx in range(3)]
    statements = [
        ailment.Stmt.Assignment(
            10,
            vvar_def,
            ailment.Expr.Load(11, addr, 4, "Iend_LE"),
            ins_addr=0x1000,
        ),
        ailment.Stmt.DirtyStatement(
            12,
            _dirty(13, mfx, maddr=addr),
            ins_addr=0x1001,
        ),
    ]
    statements.extend(
        ailment.Stmt.Assignment(20 + idx, ailment.Expr.Register(30 + idx, 24 + idx * 4, 32), use)
        for idx, use in enumerate(vvar_uses)
    )
    return ailment.Block(0x1000, 1, statements=statements, idx=0), vvar_uses


@pytest.mark.parametrize("mfx, expected_replacement", ((None, True), ("Ifx_None", False)))
def test_effectful_assignment_source_query_is_cached_per_spropagator(monkeypatch, mfx, expected_replacement):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    block, vvar_def, vvar_uses = _effect_source_switch_block(mfx)
    defining_stmt = block.statements[0]
    assert isinstance(defining_stmt, ailment.Stmt.Assignment)

    original = spropagator_module.has_effectful_dirty_expression
    calls = 0

    def counting_query(expr):
        nonlocal calls
        calls += 1
        return original(expr)

    monkeypatch.setattr(spropagator_module, "has_effectful_dirty_expression", counting_query)

    first = _function_propagator(project, block, manager)
    assert calls == 1
    cached_stmt, cached_result = first._effectful_assignment_src_cache[id(defining_stmt)]
    assert cached_stmt is defining_stmt
    assert cached_result is (mfx is not None)
    assert _has_replacement(first, vvar_uses) is expected_replacement
    if expected_replacement:
        assert vvar_def.varid in first.dead_vvar_ids

    second = _function_propagator(project, block, manager)
    assert calls == 2
    second_cached_stmt, second_cached_result = second._effectful_assignment_src_cache[id(defining_stmt)]
    assert second_cached_stmt is defining_stmt
    assert second_cached_result == cached_result
    assert second.replacements == first.replacements
    assert second.dead_vvar_ids == first.dead_vvar_ids


@pytest.mark.parametrize("mfx, expected_replacement", (("Ifx_Read", True), ("Ifx_Write", False)))
def test_dirty_write_statement_query_is_cached_per_spropagator(monkeypatch, mfx, expected_replacement):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    block, vvar_uses = _global_load_block(mfx)

    original = spropagator_module.has_dirty_memory_write
    calls_by_id: defaultdict[int, int] = defaultdict(int)

    def counting_query(stmt):
        calls_by_id[id(stmt)] += 1
        return original(stmt)

    monkeypatch.setattr(spropagator_module, "has_dirty_memory_write", counting_query)

    first = _function_propagator(project, block, manager)
    assert calls_by_id
    assert set(calls_by_id.values()) == {1}
    for stmt in block.statements:
        if id(stmt) in calls_by_id:
            assert first._dirty_memory_write_cache[id(stmt)][0] is stmt
    assert _has_replacement(first, vvar_uses) is expected_replacement

    second = _function_propagator(project, block, manager)
    assert set(calls_by_id.values()) == {2}
    for stmt in block.statements:
        if id(stmt) in calls_by_id:
            assert second._dirty_memory_write_cache[id(stmt)][0] is stmt
    assert second.replacements == first.replacements
    assert second.dead_vvar_ids == first.dead_vvar_ids
