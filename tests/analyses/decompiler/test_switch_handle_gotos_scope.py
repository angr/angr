# pylint: disable=protected-access
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import archinfo

from angr import ailment, claripy
from angr.analyses.decompiler.structurer_nodes import (
    BaseNode,
    BreakNode,
    ConditionNode,
    LoopNode,
    SequenceNode,
    SwitchCaseNode,
)
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


def _return_block(addr: int = 0x4020) -> ailment.Block:
    return ailment.Block(addr, 1, statements=[ailment.Stmt.Return(2, [], ins_addr=addr)])


def _nested_switch(cases: dict[int, Any], default: Any) -> SwitchCaseNode:
    return SwitchCaseNode(ailment.Expr.Const(3, 0, 32), cast(Any, cases), default, addr=0x4030)


def _make_structurer() -> StructurerBase:
    arch = archinfo.ArchAMD64()
    structurer = object.__new__(StructurerBase)
    structurer.project = cast(Any, SimpleNamespace(arch=arch))
    structurer.ail_manager = ailment.Manager()
    return structurer


def _is_outer_break(node: Any) -> bool:
    return type(node) is BreakNode and node.target == SWITCH_END


def _wrapped(node: Any) -> list[Any]:
    # the nested switch was replaced by a sequence carrying it and the outer break
    assert isinstance(node, SequenceNode)
    return node.nodes


def _assert_inner_break(switch: SwitchCaseNode, exit_block: ailment.Block) -> None:
    # the direct goto became a break that leaves the nested switch; insert_node wraps the arm in a sequence
    assert exit_block.statements == []
    arm = switch.default_node
    assert isinstance(arm, SequenceNode)
    assert arm.nodes[0] is exit_block
    assert _is_outer_break(arm.nodes[1])


def test_switch_goto_rewrite_handles_direct_outer_case_exit():
    exit_block = _jump_block()
    case = SequenceNode(exit_block.addr, [exit_block])

    _make_structurer()._switch_handle_gotos({0: case}, None, SWITCH_END)

    assert exit_block.statements == []
    assert len(case.nodes) == 2
    assert _is_outer_break(case.nodes[1])


def test_switch_goto_rewrite_carries_proven_outer_exit_through_nested_switch():
    exit_block = _jump_block()
    nested = _nested_switch({0: BreakNode(0x4010, SWITCH_END), 1: _return_block()}, exit_block)
    outer_case = SequenceNode(nested.addr, [nested])
    structurer = _make_structurer()

    # the second pass must not add a second outer break
    for _ in range(2):
        structurer._switch_handle_gotos({0: outer_case}, None, SWITCH_END)

    _assert_inner_break(nested, exit_block)
    assert len(outer_case.nodes) == 2
    assert outer_case.nodes[0] is nested
    assert _is_outer_break(outer_case.nodes[1])


def test_switch_goto_rewrite_replaces_proven_nested_switch_case_root():
    exit_block = _jump_block()
    nested = _nested_switch({0: BreakNode(0x4010, SWITCH_END)}, exit_block)
    cases: dict[int, BaseNode] = {0: nested}
    structurer = _make_structurer()

    for _ in range(2):
        structurer._switch_handle_gotos(cases, None, SWITCH_END)

    _assert_inner_break(nested, exit_block)
    rewritten = _wrapped(cases[0])
    assert len(rewritten) == 2
    assert rewritten[0] is nested
    assert _is_outer_break(rewritten[1])


def test_switch_goto_rewrite_wraps_proven_nested_switch_under_condition():
    exit_block = _jump_block()
    nested = _nested_switch({0: BreakNode(0x4010, SWITCH_END)}, exit_block)
    # both branches are present, so the case already ends with a transition and gains no trailing goto
    cond = ConditionNode(0x4028, None, claripy.true(), nested, false_node=_return_block(0x4040))
    outer_case = SequenceNode(cond.addr, [cond])

    _make_structurer()._switch_handle_gotos({0: outer_case}, None, SWITCH_END)

    _assert_inner_break(nested, exit_block)
    assert len(outer_case.nodes) == 1
    new_cond = outer_case.nodes[0]
    assert isinstance(new_cond, ConditionNode)
    rewritten = _wrapped(new_cond.true_node)
    assert len(rewritten) == 2
    assert rewritten[0] is nested
    assert _is_outer_break(rewritten[1])


def test_switch_goto_rewrite_leaves_nested_switch_alone_when_an_arm_falls_out():
    exit_block = _jump_block()
    inner_case = SequenceNode(exit_block.addr, [exit_block])
    nested = _nested_switch({0: inner_case}, ailment.Block(0x4020, 1, statements=[]))
    outer_case = SequenceNode(nested.addr, [nested])

    _make_structurer()._switch_handle_gotos({0: outer_case}, None, SWITCH_END)

    # the goto still becomes a break that leaves the nested switch, but no outer break follows the switch: the default
    # arm falls out of it and must not be captured
    assert exit_block.statements == []
    assert len(inner_case.nodes) == 2
    assert _is_outer_break(inner_case.nodes[1])
    assert outer_case.nodes == [nested]


def test_switch_goto_rewrite_leaves_unproven_direct_nested_exit_with_inner_break():
    exit_block = _jump_block()
    nested = _nested_switch({0: ailment.Block(0x4010, 1, statements=[])}, exit_block)
    cases: dict[int, BaseNode] = {0: nested}

    _make_structurer()._switch_handle_gotos(cases, None, SWITCH_END)

    _assert_inner_break(nested, exit_block)
    assert cases[0] is nested


def test_switch_goto_rewrite_leaves_nested_switch_inside_loop_alone():
    exit_block = _jump_block()
    nested = _nested_switch({0: BreakNode(0x4010, SWITCH_END)}, exit_block)
    body = SequenceNode(nested.addr, [nested])
    loop = LoopNode("while", None, body, addr=0x4028)
    outer_case = SequenceNode(loop.addr, [loop])

    _make_structurer()._switch_handle_gotos({0: outer_case}, None, SWITCH_END)

    # a break after the nested switch would leave the loop, not the outer switch
    _assert_inner_break(nested, exit_block)
    assert body.nodes == [nested]


def test_switch_goto_rewrite_leaves_switch_nested_in_a_nested_switch_alone():
    exit_block = _jump_block()
    nested = _nested_switch({0: BreakNode(0x4010, SWITCH_END)}, exit_block)
    middle = SwitchCaseNode(ailment.Expr.Const(4, 0, 32), cast(Any, {0: nested}), _return_block(0x4040), addr=0x4028)
    outer_case = SequenceNode(middle.addr, [middle])

    _make_structurer()._switch_handle_gotos({0: outer_case}, None, SWITCH_END)

    # a break after the inner switch would leave the middle switch, not the outer one, and the middle switch has an
    # arm holding a switch, which the proof does not look through
    _assert_inner_break(nested, exit_block)
    assert middle.cases[0] is nested
    assert outer_case.nodes == [middle]


def test_switch_goto_rewrite_rewrites_nested_default_root_in_place():
    exit_block = _jump_block()
    nested = _nested_switch({0: BreakNode(0x4010, SWITCH_END)}, exit_block)

    _make_structurer()._switch_handle_gotos({}, nested, SWITCH_END)

    # the default node is rendered last, so leaving the nested switch is leaving the outer one; the arms are still
    # rewritten in place
    _assert_inner_break(nested, exit_block)
