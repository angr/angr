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


def test_dirty_effect_classification_preserves_vex_semantics():
    pure = _dirty(0, None)
    guest_state_effect = _dirty(1, "Ifx_None")
    read = _dirty(2, "Ifx_Read")
    write = _dirty(3, "Ifx_Write")
    modify = _dirty(4, "Ifx_Modify")

    assert not is_effectful_dirty_expression(pure)
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
        walker.walk_expression(_dirty(21, "Ifx_None"))

    with pytest.raises(HasCallNotification):
        walker.walk_expression(_dirty(22, None, operands=(_dirty(23, "Ifx_Write"),)))


@pytest.mark.parametrize("nested_effectful", (False, True))
def test_effectful_dirty_definition_protects_entire_cyclic_vvar_component(nested_effectful):
    project = _project()
    vvar_1_def = VirtualVariable(0, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_1_use = VirtualVariable(1, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_2_def = VirtualVariable(2, 2, 64, VirtualVariableCategory.REGISTER, oident=24)
    vvar_2_use = VirtualVariable(3, 2, 64, VirtualVariableCategory.REGISTER, oident=24)

    operands = [vvar_2_use]
    if nested_effectful:
        operands.append(_dirty(4, "Ifx_None"))
    dirty = _dirty(5, None, operands=operands)
    phi = ailment.Expr.Phi(6, 64, [((0x1000, 0), vvar_1_use)])
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(7, vvar_1_def, dirty),
            ailment.Stmt.Assignment(8, vvar_2_def, phi),
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

    assert removable == (set() if nested_effectful else {1, 2})


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


def test_spropagator_does_not_propagate_effectful_dirty_tmp():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    tmp_def = ailment.Expr.Tmp(0, 0, 64)
    tmp_use = ailment.Expr.Tmp(1, 0, 64)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(2, tmp_def, _dirty(3, "Ifx_None"), ins_addr=0x1000),
            ailment.Stmt.Assignment(4, ailment.Expr.Register(5, 16, 64), tmp_use, ins_addr=0x1001),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert not _has_replacement(propagator, (tmp_use,))


@pytest.mark.parametrize("mfx, expected_replacement", (("Ifx_Read", True), ("Ifx_Write", False)))
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
            ailment.Stmt.Assignment(
                5,
                ailment.Expr.Tmp(6, 1, 64),
                _dirty(7, mfx, maddr=addr),
                ins_addr=0x1001,
            ),
            ailment.Stmt.Assignment(8, ailment.Expr.Register(9, 16, 32), tmp_use, ins_addr=0x1002),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert _has_replacement(propagator, (tmp_use,)) is expected_replacement


@pytest.mark.parametrize("use_count", (1, 3))
@pytest.mark.parametrize("mfx, expected_replacement", (("Ifx_Read", True), ("Ifx_Modify", False)))
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
        ailment.Stmt.Assignment(
            12,
            ailment.Expr.Tmp(13, 0, 64),
            _dirty(14, mfx, maddr=addr),
            ins_addr=0x1001,
        ),
    ]
    statements.extend(
        ailment.Stmt.Assignment(20 + idx, ailment.Expr.Register(30 + idx, 24 + idx * 4, 32), use, ins_addr=0x1002 + idx)
        for idx, use in enumerate(vvar_uses)
    )
    block = ailment.Block(0x1000, 1, statements=statements, idx=0)

    propagator = _function_propagator(project, block, manager)
    assert _has_replacement(propagator, vvar_uses) is expected_replacement
