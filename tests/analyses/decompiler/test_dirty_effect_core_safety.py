from __future__ import annotations

import networkx
import pytest

import angr
from angr import ailment
from angr.ailment.expression import DirtyExpression, VirtualVariable, VirtualVariableCategory
from angr.ailment.utils import (
    has_dirty_memory_read,
    has_dirty_memory_write,
    has_effectful_dirty_expression,
    is_effectful_dirty_expression,
)
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.analyses.decompiler.block_walkers import HasCallExprWalker, HasCallNotification
from angr.analyses.s_propagator import SPropagator
from angr.analyses.s_reaching_definitions import SRDAModel
from angr.code_location import AILCodeLocation


def _project():
    return angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)


def _dirty(
    idx: int,
    mfx: str | None,
    *,
    operands=(),
    guard=None,
    maddr=None,
    bits: int = 64,
) -> DirtyExpression:
    return DirtyExpression(
        idx,
        f"helper_{idx}",
        list(operands),
        guard=guard,
        mfx=mfx,
        maddr=maddr,
        msize=8 if maddr is not None else None,
        bits=bits,
    )


def _has_replacement(propagator: SPropagator, expressions) -> bool:
    return any(expr in replacements for replacements in propagator.replacements.values() for expr in expressions)


def _function_propagator(project, block: ailment.Block, manager: ailment.Manager) -> SPropagator:
    function = project.kb.functions.function(addr=block.addr, create=True)
    assert function is not None
    graph = networkx.DiGraph()
    graph.add_node(block)
    return SPropagator(project, subject=function, func_graph=graph, ail_manager=manager)


def _intervening_dirty_statement(idx: int, mfx: str | None, addr):
    return ailment.Stmt.DirtyStatement(
        idx,
        _dirty(idx + 1, mfx, maddr=addr if mfx is not None else None),
        ins_addr=0x1001,
    )


def _mse_use_with_dirty_write(idx: int, use, addr):
    write = ailment.Stmt.DirtyStatement(
        idx,
        _dirty(idx + 1, "Ifx_Write", maddr=addr),
        ins_addr=0x1001,
    )
    return ailment.Expr.MultiStatementExpression(idx + 2, [write], use)


def test_dirty_effect_classification_preserves_vex_semantics():
    pure = _dirty(0, None)
    guest_state_effect = _dirty(1, "Ifx_None")
    read = _dirty(2, "Ifx_Read")
    write = _dirty(3, "Ifx_Write")
    modify = _dirty(4, "Ifx_Modify")

    assert not is_effectful_dirty_expression(pure)
    assert not has_effectful_dirty_expression(pure)
    assert not has_dirty_memory_read(pure)
    assert not has_dirty_memory_write(pure)
    assert is_effectful_dirty_expression(guest_state_effect)
    assert has_effectful_dirty_expression(guest_state_effect)
    assert not has_dirty_memory_read(guest_state_effect)
    assert not has_dirty_memory_write(guest_state_effect)

    assert has_dirty_memory_read(read)
    assert not has_dirty_memory_write(read)
    assert not has_dirty_memory_read(write)
    assert has_dirty_memory_write(write)
    assert has_dirty_memory_read(modify)
    assert has_dirty_memory_write(modify)

    opaque_stmt = ailment.Stmt.DirtyStatement(5, pure)
    nested_stmt = ailment.Expr.MultiStatementExpression(6, [opaque_stmt], ailment.Expr.Const(7, 0, 64))
    assert has_effectful_dirty_expression(nested_stmt)
    assert has_dirty_memory_read(nested_stmt)
    assert has_dirty_memory_write(nested_stmt)


@pytest.mark.parametrize(
    "mfx, expected_read, expected_write",
    (
        (None, True, True),
        ("Ifx_None", False, False),
        ("Ifx_Read", True, False),
        ("Ifx_Write", False, True),
        ("Ifx_Modify", True, True),
    ),
)
def test_dirty_statement_memory_effect_truth_table(mfx, expected_read, expected_write):
    stmt = ailment.Stmt.DirtyStatement(8, _dirty(9, mfx))

    assert has_effectful_dirty_expression(stmt)
    assert has_dirty_memory_read(stmt) is expected_read
    assert has_dirty_memory_write(stmt) is expected_write


def test_dirty_effect_search_recurses_through_nonmatching_dirty_fields():
    nested_write = _dirty(10, "Ifx_Write")
    roots = (
        _dirty(11, "Ifx_Read", operands=(nested_write,)),
        _dirty(12, None, guard=nested_write),
        _dirty(13, "Ifx_None", maddr=nested_write),
    )

    for root in roots:
        assert has_effectful_dirty_expression(root)
        assert has_dirty_memory_write(root)

    assert not is_effectful_dirty_expression(roots[1])


def test_has_call_walker_treats_ifx_none_and_nested_dirty_as_effects():
    walker = HasCallExprWalker()
    walker.walk_expression(_dirty(20, None))

    with pytest.raises(HasCallNotification):
        walker.walk_statement(ailment.Stmt.DirtyStatement(21, _dirty(22, None)))

    with pytest.raises(HasCallNotification):
        walker.walk_expression(_dirty(23, "Ifx_None"))

    with pytest.raises(HasCallNotification):
        walker.walk_expression(_dirty(24, None, operands=(_dirty(25, "Ifx_Write"),)))


@pytest.mark.parametrize("dst_kind", ("tmp", "register"))
def test_block_simplifier_preserves_unused_ifx_none_dirty_assignment(dst_kind):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    dst = ailment.Expr.Tmp(0, 0, 64) if dst_kind == "tmp" else ailment.Expr.Register(0, 16, 64)
    effect = _dirty(1, "Ifx_None")
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(2, dst, effect, ins_addr=0x1000),
            ailment.Stmt.Return(3, [], ins_addr=0x1001),
        ],
        idx=0,
    )

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block

    assert simplified is not None
    assert any(
        isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.src, DirtyExpression)
        and stmt.src.callee == effect.callee
        for stmt in simplified.statements
    )


def test_block_simplifier_preserves_unused_mse_with_opaque_dirty_statement():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    opaque_stmt = ailment.Stmt.DirtyStatement(0, _dirty(1, None), ins_addr=0x1000)
    mse = ailment.Expr.MultiStatementExpression(2, [opaque_stmt], ailment.Expr.Const(3, 0, 64))
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(4, ailment.Expr.Tmp(5, 0, 64), mse, ins_addr=0x1000),
            ailment.Stmt.Return(6, [], ins_addr=0x1001),
        ],
        idx=0,
    )

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block

    assert simplified is not None
    assert any(
        isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.MultiStatementExpression)
        for stmt in simplified.statements
    )


def test_block_simplifier_removes_unused_pure_dirty_expression():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    pure = _dirty(0, None)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(1, ailment.Expr.Tmp(2, 0, 64), pure, ins_addr=0x1000),
            ailment.Stmt.Return(3, [], ins_addr=0x1001),
        ],
        idx=0,
    )

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block

    assert simplified is not None
    assert not any(
        isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.src, DirtyExpression)
        and stmt.src.callee == pure.callee
        for stmt in simplified.statements
    )


def test_block_simplifier_propagates_pure_dirty_expression():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    tmp_def = ailment.Expr.Tmp(0, 0, 64)
    tmp_use = ailment.Expr.Tmp(1, 0, 64)
    pure = _dirty(2, None)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(3, tmp_def, pure, ins_addr=0x1000),
            ailment.Stmt.Assignment(4, ailment.Expr.Register(5, 16, 64), tmp_use, ins_addr=0x1001),
            ailment.Stmt.Return(6, [], ins_addr=0x1002),
        ],
        idx=0,
    )

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block

    assert simplified is not None
    assert not any(
        isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.dst, ailment.Expr.Tmp)
        and stmt.dst.tmp_idx == tmp_def.tmp_idx
        for stmt in simplified.statements
    )
    assert any(
        isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.dst, ailment.Expr.Register)
        and isinstance(stmt.src, DirtyExpression)
        and stmt.src.callee == pure.callee
        for stmt in simplified.statements
    )


@pytest.mark.parametrize("source_kind", ("pure", "nested_dirty", "converted_dirty", "dirty_statement_mse"))
def test_effectful_dirty_definition_protects_entire_cyclic_vvar_component(source_kind):
    project = _project()
    vvar_1_def = VirtualVariable(0, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_1_use = VirtualVariable(1, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_2_def = VirtualVariable(2, 2, 64, VirtualVariableCategory.REGISTER, oident=24)
    vvar_2_use = VirtualVariable(3, 2, 64, VirtualVariableCategory.REGISTER, oident=24)

    if source_kind == "pure":
        source = _dirty(4, None, operands=(vvar_2_use,))
    elif source_kind == "nested_dirty":
        source = _dirty(5, None, operands=(vvar_2_use, _dirty(6, "Ifx_None")))
    elif source_kind == "converted_dirty":
        inner = ailment.Expr.BinaryOp(7, "Add", [vvar_2_use, _dirty(8, "Ifx_None")], bits=64)
        source = ailment.Expr.Convert(9, 64, 64, False, inner)
    else:
        opaque_stmt = ailment.Stmt.DirtyStatement(10, _dirty(11, None))
        source = ailment.Expr.MultiStatementExpression(12, [opaque_stmt], vvar_2_use)
    phi = ailment.Expr.Phi(6, 64, [((0x1000, 0), vvar_1_use)])
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(13, vvar_1_def, source),
            ailment.Stmt.Assignment(14, vvar_2_def, phi),
        ],
        idx=0,
    )
    graph = networkx.DiGraph()
    graph.add_node(block)

    rd = SRDAModel(graph, None, project.arch)
    rd.varid_to_vvar = {1: vvar_1_def, 2: vvar_2_def}
    rd.phi_vvar_ids = {2}
    rd.phivarid_to_varids = {2: {1}}
    rd.all_vvar_uses[1].append((vvar_1_use, AILCodeLocation(block.addr, block.idx, 1)))
    rd.all_vvar_uses[2].append((vvar_2_use, AILCodeLocation(block.addr, block.idx, 0)))

    simplifier = object.__new__(AILSimplifier)
    simplifier.func_graph = graph
    removable = simplifier._find_cyclic_dependent_phis_and_dirty_vvars(rd, set())

    assert removable == ({1, 2} if source_kind == "pure" else set())


def test_spropagator_guards_forced_stack_and_independent_vvar_paths():
    project = _project()
    manager = ailment.Manager(arch=project.arch)

    stack_def = VirtualVariable(0, 1, 64, VirtualVariableCategory.STACK, oident=-8)
    stack_use = VirtualVariable(1, 1, 64, VirtualVariableCategory.STACK, oident=-8)
    stack_block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(2, stack_def, _dirty(3, "Ifx_None"), ins_addr=0x1000),
            ailment.Stmt.Return(4, [stack_use], ins_addr=0x1001),
        ],
        idx=0,
    )
    stack_prop = SPropagator(
        project,
        subject=stack_block,
        ail_manager=manager,
        stack_arg_offsets={-8},
    )
    assert not _has_replacement(stack_prop, (stack_use,))

    vvar_def = VirtualVariable(5, 2, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_0 = VirtualVariable(6, 2, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_1 = VirtualVariable(7, 2, 64, VirtualVariableCategory.REGISTER, oident=16)
    nested_effect = _dirty(8, None, operands=(_dirty(9, "Ifx_Write"),))
    vvar_block = ailment.Block(
        0x2000,
        1,
        statements=[
            ailment.Stmt.Assignment(10, vvar_def, nested_effect, ins_addr=0x2000),
            ailment.Stmt.ConditionalJump(
                11,
                vvar_use_0,
                ailment.Expr.Const(12, 0x2000, 64),
                ailment.Expr.Const(13, 0x3000, 64),
                true_target_idx=0,
                ins_addr=0x2001,
            ),
            ailment.Stmt.Jump(14, vvar_use_1, ins_addr=0x2002),
        ],
        idx=0,
    )
    vvar_prop = _function_propagator(project, vvar_block, manager)
    assert not _has_replacement(vvar_prop, (vvar_use_0, vvar_use_1))
    assert vvar_def.varid not in vvar_prop.dead_vvar_ids


@pytest.mark.parametrize(
    "mfx, expected_replacement",
    (("Ifx_Read", True), ("Ifx_Write", False), (None, False)),
)
def test_spropagator_switch_path_does_not_bypass_load_memory_safety(mfx, expected_replacement):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    vvar_def = VirtualVariable(1, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_0 = VirtualVariable(2, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_1 = VirtualVariable(3, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    block = ailment.Block(
        0x2000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                4,
                vvar_def,
                ailment.Expr.Load(5, addr, 8, "Iend_LE"),
                ins_addr=0x2000,
            ),
            _intervening_dirty_statement(6, mfx, addr),
            ailment.Stmt.ConditionalJump(
                8,
                vvar_use_0,
                ailment.Expr.Const(9, 0x2000, 64),
                ailment.Expr.Const(10, 0x3000, 64),
                true_target_idx=0,
                ins_addr=0x2001,
            ),
            ailment.Stmt.Jump(11, vvar_use_1, ins_addr=0x2002),
        ],
        idx=0,
    )

    propagator = _function_propagator(project, block, manager)
    assert _has_replacement(propagator, (vvar_use_0, vvar_use_1)) is expected_replacement
    if not expected_replacement:
        assert vvar_def.varid not in propagator.dead_vvar_ids


@pytest.mark.parametrize("source_kind", ("ifx_none", "dirty_statement"))
def test_spropagator_does_not_propagate_effectful_dirty_tmp(source_kind):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    tmp_def = ailment.Expr.Tmp(0, 0, 64)
    tmp_use = ailment.Expr.Tmp(1, 0, 64)
    if source_kind == "ifx_none":
        source = _dirty(3, "Ifx_None")
    else:
        opaque_stmt = ailment.Stmt.DirtyStatement(3, _dirty(4, None))
        source = ailment.Expr.MultiStatementExpression(5, [opaque_stmt], ailment.Expr.Const(6, 0, 64))
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(7, tmp_def, source, ins_addr=0x1000),
            ailment.Stmt.Assignment(8, ailment.Expr.Register(9, 16, 64), tmp_use, ins_addr=0x1001),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert not _has_replacement(propagator, (tmp_use,))


@pytest.mark.parametrize(
    "mfx, expected_replacement",
    (("Ifx_Read", True), ("Ifx_Write", False), (None, False)),
)
def test_spropagator_tmp_load_crosses_reads_but_not_dirty_writes(mfx, expected_replacement):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    tmp_def = ailment.Expr.Tmp(1, 0, 32)
    tmp_use = ailment.Expr.Tmp(2, 0, 32)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                3,
                tmp_def,
                ailment.Expr.Load(4, addr, 4, "Iend_LE"),
                ins_addr=0x1000,
            ),
            _intervening_dirty_statement(5, mfx, addr),
            ailment.Stmt.Assignment(8, ailment.Expr.Register(9, 16, 32), tmp_use, ins_addr=0x1002),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert _has_replacement(propagator, (tmp_use,)) is expected_replacement


def test_spropagator_does_not_move_tmp_load_past_dirty_write_in_use_mse():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    tmp_def = ailment.Expr.Tmp(1, 0, 32)
    tmp_use = ailment.Expr.Tmp(2, 0, 32)
    use_mse = _mse_use_with_dirty_write(3, tmp_use, addr)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                6,
                tmp_def,
                ailment.Expr.Load(7, addr, 4, "Iend_LE"),
                ins_addr=0x1000,
            ),
            ailment.Stmt.Assignment(8, ailment.Expr.Register(9, 16, 32), use_mse, ins_addr=0x1001),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert not _has_replacement(propagator, (tmp_use,))


@pytest.mark.parametrize("use_count", (1, 3))
@pytest.mark.parametrize(
    "mfx, expected_replacement",
    (("Ifx_Read", True), ("Ifx_Modify", False), (None, False)),
)
def test_spropagator_function_load_crosses_reads_but_not_dirty_writes(mfx, expected_replacement, use_count):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    vvar_def = VirtualVariable(1, 1, 32, VirtualVariableCategory.REGISTER, oident=16)
    vvar_uses = [
        VirtualVariable(idx + 2, 1, 32, VirtualVariableCategory.REGISTER, oident=16) for idx in range(use_count)
    ]
    statements = [
        ailment.Stmt.Assignment(
            10,
            vvar_def,
            ailment.Expr.Load(11, addr, 4, "Iend_LE"),
            ins_addr=0x1000,
        ),
        _intervening_dirty_statement(12, mfx, addr),
    ]
    statements.extend(
        ailment.Stmt.Assignment(20 + idx, ailment.Expr.Register(30 + idx, 24 + idx * 4, 32), use, ins_addr=0x1002 + idx)
        for idx, use in enumerate(vvar_uses)
    )
    block = ailment.Block(0x1000, 1, statements=statements, idx=0)

    propagator = _function_propagator(project, block, manager)
    assert _has_replacement(propagator, vvar_uses) is expected_replacement


@pytest.mark.parametrize("use_count", (1, 3))
def test_spropagator_does_not_move_function_load_past_dirty_write_in_use_mse(use_count):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    vvar_def = VirtualVariable(1, 1, 32, VirtualVariableCategory.REGISTER, oident=16)
    vvar_uses = [
        VirtualVariable(idx + 2, 1, 32, VirtualVariableCategory.REGISTER, oident=16) for idx in range(use_count)
    ]
    statements = [
        ailment.Stmt.Assignment(
            10,
            vvar_def,
            ailment.Expr.Load(11, addr, 4, "Iend_LE"),
            ins_addr=0x1000,
        )
    ]
    statements.extend(
        ailment.Stmt.Assignment(
            20 + idx,
            ailment.Expr.Register(30 + idx, 24 + idx * 4, 32),
            _mse_use_with_dirty_write(40 + idx * 3, use, addr) if idx == 0 else use,
            ins_addr=0x1001 + idx,
        )
        for idx, use in enumerate(vvar_uses)
    )
    block = ailment.Block(0x1000, 1, statements=statements, idx=0)

    propagator = _function_propagator(project, block, manager)
    assert not _has_replacement(propagator, vvar_uses)
