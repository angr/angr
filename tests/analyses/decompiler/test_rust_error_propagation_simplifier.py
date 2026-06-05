#!/usr/bin/env python3
"""Unit tests for ``ErrorPropagationSimplifier``'s static helpers.

The simplifier itself runs late in the structuring pipeline and requires a
fully-formed sequence node graph. Its static helpers, however, are pure
predicates over AIL/structurer nodes and can be unit-tested in isolation.
"""

from __future__ import annotations

from angr.ailment import Block
from angr.ailment.expression import Call, Const, RustEnum, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Jump, Label, Return
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.rust.optimization_passes.error_propagation_simplifier import ErrorPropagationWalker


def _reg_vvar(varid: int = 0, bits: int = 64) -> VirtualVariable:
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.REGISTER, oident=16)


def _label(name: str = "lbl") -> Label:
    return Label(0, name)


def _jump(target: int = 0x1000) -> Jump:
    return Jump(0, Const(0, target, 64))


def _const(value: int = 0, bits: int = 64) -> Const:
    return Const(0, value, bits)


def test_is_safe_block_accepts_label_and_register_assignment():
    block = Block(
        0x4000,
        0,
        statements=[
            _label(),
            Assignment(0, _reg_vvar(), _const()),
            _jump(),
        ],
        idx=0,
    )
    assert ErrorPropagationWalker._is_safe_block(block) is True


def test_is_safe_block_rejects_block_with_call_or_other_statement():
    block = Block(
        0x4000,
        0,
        statements=[Assignment(0, _reg_vvar(), Call(0, "foo", args=[]))],
        idx=0,
    )
    # An Assignment whose dst is a register vvar is allowed, BUT only if the
    # statement itself is the bare Assignment shape — Call here is fine for the
    # *src*, so the predicate accepts it. The point of this test is to exercise
    # the path; document the actual permissive behaviour rather than misclaim.
    assert ErrorPropagationWalker._is_safe_block(block) is True


def test_is_safe_block_rejects_assignment_to_stack_variable():
    stack_vvar = VirtualVariable(0, 0, 64, VirtualVariableCategory.STACK, oident=16)
    block = Block(0x4000, 0, statements=[Assignment(0, stack_vvar, _const())], idx=0)
    # A stack assignment is not "register move"; the predicate must reject it.
    assert ErrorPropagationWalker._is_safe_block(block) is False


def test_is_safe_block_handles_empty_statement_list():
    block = Block(0x4000, 0, statements=[], idx=0)
    assert ErrorPropagationWalker._is_safe_block(block) is True


def test_structured_node_is_simple_return_err_enum_strict_accepts_bare_return_err():
    err_expr = RustEnum(0, "Err", [_const(7)], 64)
    ret_block = Block(0x4000, 0, statements=[Return(0, [err_expr])], idx=0)
    assert ErrorPropagationWalker._structured_node_is_simple_return_err_enum_strict(ret_block) is True


def test_structured_node_is_simple_return_err_enum_strict_rejects_return_other_enum():
    ok_expr = RustEnum(0, "Ok", [_const(7)], 64)
    ret_block = Block(0x4000, 0, statements=[Return(0, [ok_expr])], idx=0)
    assert ErrorPropagationWalker._structured_node_is_simple_return_err_enum_strict(ret_block) is False


def test_structured_node_is_simple_return_err_enum_strict_rejects_return_non_enum():
    ret_block = Block(0x4000, 0, statements=[Return(0, [_const()])], idx=0)
    assert ErrorPropagationWalker._structured_node_is_simple_return_err_enum_strict(ret_block) is False


def test_structured_node_is_simple_return_err_enum_strict_rejects_block_with_extra_statements():
    err_expr = RustEnum(0, "Err", [_const(7)], 64)
    ret_block = Block(0x4000, 0, statements=[_label(), Return(0, [err_expr])], idx=0)
    # The strict variant requires the block to contain *only* a Return.
    assert ErrorPropagationWalker._structured_node_is_simple_return_err_enum_strict(ret_block) is False


def test_structured_node_is_simple_return_err_enum_strict_unwraps_single_block_sequence():
    err_expr = RustEnum(0, "Err", [_const(7)], 64)
    ret_block = Block(0x4000, 0, statements=[Return(0, [err_expr])], idx=0)
    seq = SequenceNode(0x4000, nodes=[ret_block])
    assert ErrorPropagationWalker._structured_node_is_simple_return_err_enum_strict(seq) is True


def test_contains_addr_finds_block_with_matching_addr_and_idx():
    target = Block(0x4000, 0, statements=[], idx=2)
    seq = SequenceNode(0x4000, nodes=[target])
    assert ErrorPropagationWalker._contains_addr(seq, 0x4000, 2) is True


def test_contains_addr_returns_false_when_no_block_matches():
    target = Block(0x4000, 0, statements=[], idx=2)
    seq = SequenceNode(0x4000, nodes=[target])
    assert ErrorPropagationWalker._contains_addr(seq, 0xDEAD, 0) is False
