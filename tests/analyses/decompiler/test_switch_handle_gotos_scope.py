from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest

from angr import ailment
from angr.analyses.decompiler.structurer_nodes import BreakNode, SequenceNode, SwitchCaseNode
from angr.analyses.decompiler.structuring.structurer_base import StructurerBase

SWITCH_END = 0x5000


def _jump_block(addr: int = 0x4000) -> ailment.Block:
    return ailment.Block(
        addr,
        1,
        statements=[
            ailment.Stmt.Jump(
                0,
                ailment.Expr.Const(1, SWITCH_END, 64),
                target_idx=None,
                ins_addr=addr,
            )
        ],
    )


def _make_structurer() -> StructurerBase:
    arch = archinfo.ArchAMD64()
    structurer = object.__new__(StructurerBase)
    structurer.project = SimpleNamespace(arch=arch)
    structurer.ail_manager = ailment.Manager(arch=arch)
    return structurer


def test_switch_goto_rewrite_handles_direct_outer_case_exit():
    exit_block = _jump_block()
    case = SequenceNode(exit_block.addr, [exit_block])

    _make_structurer()._switch_handle_gotos({0: case}, None, SWITCH_END)

    assert exit_block.statements == []
    assert type(case.nodes[1]) is BreakNode
    assert case.nodes[1].target == SWITCH_END


def test_switch_goto_rewrite_carries_proven_outer_exit_through_nested_switch():
    exit_block = _jump_block()
    inner_break = BreakNode(0x4010, SWITCH_END)
    returning_case = ailment.Block(
        0x4020,
        1,
        statements=[ailment.Stmt.Return(2, [], ins_addr=0x4020)],
    )
    nested = SwitchCaseNode(
        ailment.Expr.Const(3, 0, 32),
        {0: inner_break, 1: returning_case},
        exit_block,
        addr=0x4030,
    )
    outer_case = SequenceNode(nested.addr, [nested])
    structurer = _make_structurer()

    for _ in range(2):
        structurer._switch_handle_gotos({0: outer_case}, None, SWITCH_END)

    assert len(exit_block.statements) == 1
    rewritten = outer_case.nodes[0]
    assert isinstance(rewritten, SequenceNode)
    assert rewritten.nodes[0] is nested
    assert type(rewritten.nodes[1]) is BreakNode
    assert rewritten.nodes[1].target == SWITCH_END


def test_switch_goto_rewrite_replaces_proven_nested_switch_case_root():
    exit_block = _jump_block()
    nested = SwitchCaseNode(
        ailment.Expr.Const(3, 0, 32),
        {0: BreakNode(0x4010, SWITCH_END)},
        exit_block,
        addr=0x4030,
    )
    cases = {0: nested}
    structurer = _make_structurer()

    for _ in range(2):
        structurer._switch_handle_gotos(cases, None, SWITCH_END)

    assert len(exit_block.statements) == 1
    rewritten = cases[0]
    assert isinstance(rewritten, SequenceNode)
    assert rewritten.nodes[0] is nested
    assert type(rewritten.nodes[1]) is BreakNode
    assert rewritten.nodes[1].target == SWITCH_END


def test_switch_goto_rewrite_preserves_existing_path_without_direct_switch_child():
    exit_block = _jump_block()
    inner_case = SequenceNode(exit_block.addr, [exit_block])
    nested = SwitchCaseNode(
        ailment.Expr.Const(3, 0, 32),
        {0: inner_case},
        ailment.Block(0x4020, 1, statements=[]),
        addr=0x4030,
    )
    outer_case = SequenceNode(nested.addr, [nested])

    _make_structurer()._switch_handle_gotos({0: outer_case}, None, SWITCH_END)

    assert exit_block.statements == []
    assert type(inner_case.nodes[1]) is BreakNode
    assert inner_case.nodes[1].target == SWITCH_END


def test_switch_goto_rewrite_rejects_unproven_nested_switch_exit():
    exit_block = _jump_block()
    nested = SwitchCaseNode(
        ailment.Expr.Const(3, 0, 32),
        {0: ailment.Block(0x4010, 1, statements=[])},
        exit_block,
        addr=0x4030,
    )

    with pytest.raises(TypeError, match="Unsupported label value"):
        _make_structurer()._switch_handle_gotos({0: nested}, None, SWITCH_END)

    assert len(exit_block.statements) == 1


def test_switch_goto_rewrite_does_not_drop_outer_break_for_default_root():
    exit_block = _jump_block()
    nested = SwitchCaseNode(
        ailment.Expr.Const(3, 0, 32),
        {0: BreakNode(0x4010, SWITCH_END)},
        exit_block,
        addr=0x4030,
    )

    with pytest.raises(TypeError, match="Unsupported label value"):
        _make_structurer()._switch_handle_gotos({}, nested, SWITCH_END)

    assert len(exit_block.statements) == 1
