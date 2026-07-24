#!/usr/bin/env python3
# pylint: disable=protected-access
"""Unit tests for the smaller Rust optimization passes.

The passes targeted here are the ones whose logic is small or whose pure
helpers can be exercised without a real ``Decompiler`` setup. End-to-end
behaviour is covered by the integration tests in ``test_rust_decompiler.py``.

Passes whose entire logic is wrapped in walker closures with no extractable
helper (``redundant_block_remover``, ``combo_register_rewriter``) are
exercised only through integration; their predicates aren't isolatable
without spinning up a full ``OptimizationPass`` instance.
"""

from __future__ import annotations

from collections import OrderedDict

import networkx
import pytest

import angr
from angr.ailment import Block
from angr.ailment.expression import Call, Const, Insert, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Jump, Label, SideEffectStatement, Statement
from angr.calling_conventions import SimRegArg, SimStructArg
from angr.rust.optimization_passes.cleanup_code_remover import (
    CLEANUP_FUNCTIONS,
    CleanupCodeRemover,
)
from angr.rust.optimization_passes.ret_expr_rewriter import RetExprRewriter
from angr.rust.optimization_passes.security_check_remover import SECURITY_CHECK_FUNCTIONS
from angr.sim_type import SimStruct, SimTypeLongLong
from angr.utils.ssa import CALL_RESULT_FIXUP_TAG


def _two_field_struct(name: str = "Pair") -> SimStruct:
    return SimStruct(OrderedDict({"a": SimTypeLongLong(), "b": SimTypeLongLong()}), name=name, pack=True)


def _label_stmt(name: str = "lbl") -> Label:
    return Label(0, name)


def _jump_stmt(target_addr: int = 0x1000) -> Jump:
    return Jump(0, Const(0, target_addr, 64))


def test_cleanup_functions_list_covers_known_dealloc_and_drop_names():
    # Sanity: the list must include both the C-level dealloc shims and the Rust
    # drop-glue trampolines. If any of these get renamed in production code,
    # this test surfaces the drift before integration tests do.
    expected_subset = {
        "free",
        "__rust_dealloc",
        "core::ptr::drop_in_place",
        "core::ops::drop::Drop::drop",
    }
    assert expected_subset.issubset(set(CLEANUP_FUNCTIONS))


def test_cleanup_functions_list_has_no_duplicates():
    assert len(CLEANUP_FUNCTIONS) == len(set(CLEANUP_FUNCTIONS))


def test_cleanup_is_simple_block_accepts_label_only_prefix():
    # _is_simple_block returns True iff every statement *except the last* is a
    # Label — used to decide whether a block is purely a cleanup-call wrapper
    # safe to drop entirely.
    block = Block(0x4000, 0, statements=[_label_stmt(), _label_stmt(), _jump_stmt()])
    assert CleanupCodeRemover._is_simple_block(block) is True


def test_cleanup_is_simple_block_rejects_non_label_prefix():
    # A non-Label statement before the terminator means the block has work to
    # do beyond the cleanup call and must not be dropped wholesale.
    block = Block(0x4000, 0, statements=[_jump_stmt(0x100), _jump_stmt(0x200)])
    assert CleanupCodeRemover._is_simple_block(block) is False


def test_cleanup_is_simple_block_handles_empty_block():
    # An empty block has no non-terminator statements to inspect, so the
    # all(...) over an empty iterable returns True. Documenting this.
    block = Block(0x4000, 0, statements=[])
    assert CleanupCodeRemover._is_simple_block(block) is True


def test_cleanup_is_simple_block_treats_single_statement_as_terminator_only():
    # A one-statement block has no prefix, so the predicate must accept it
    # regardless of the statement type.
    block = Block(0x4000, 0, statements=[_jump_stmt()])
    assert CleanupCodeRemover._is_simple_block(block) is True


def _reg_vvar(varid: int, reg_offset: int, bits: int = 64) -> VirtualVariable:
    return VirtualVariable(0, varid, bits, VirtualVariableCategory.REGISTER, oident=reg_offset)


@pytest.mark.parametrize("folded_call", (False, True))
def test_cleanup_remover_drops_semantic_call_and_tagged_result_suffix(folded_call):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    target = 0x2000
    callee = project.kb.functions.function(addr=target, create=True)
    assert callee is not None
    callee.name = "free"

    setup = Assignment(0, _reg_vvar(1, project.arch.registers["rbx"][0]), Const(1, 1, 64))
    call = Call(2, Const(3, target, 64), args=[], bits=64)
    raw_result = _reg_vvar(2, project.arch.registers["rax"][0])
    final_result = _reg_vvar(3, project.arch.registers["rax"][0], bits=128)
    fixup = Assignment(
        4,
        final_result,
        Insert(
            5,
            Const(6, 0, 128),
            Const(7, 0, 64),
            call if folded_call else raw_result,
            project.arch.register_endness,
        ),
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    trailing_fixup = Assignment(
        8,
        _reg_vvar(4, project.arch.registers["xmm0"][0], bits=128),
        Const(9, 0, 128),
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    statements: list[Statement] = (
        [setup, fixup, trailing_fixup]
        if folded_call
        else [setup, SideEffectStatement(10, call, ret_expr=raw_result), fixup]
    )
    block = Block(0x1000, 1, statements=statements)
    remover = object.__new__(CleanupCodeRemover)
    remover._project = project
    func = project.kb.functions.function(addr=block.addr, create=True)
    assert func is not None
    remover._func = func
    remover._graph = networkx.DiGraph()
    remover._graph.add_node(block)

    remover._remove_cleanup_calls()

    assert len(block.statements) == 1
    assert block.statements[0].likes(setup)


def test_security_check_functions_list_covers_panic_branches():
    # The pass strips control-flow that ends in any of these well-known panic
    # entry points. Lock down the exact names so silent renames don't slip
    # through.
    expected = {
        "core::panicking::panic_bounds_check",
        "core::str::slice_error_fail",
        "core::panicking::panic_const::panic_const_div_by_zero",
    }
    assert expected.issubset(set(SECURITY_CHECK_FUNCTIONS))


def test_security_check_functions_list_has_no_duplicates():
    assert len(SECURITY_CHECK_FUNCTIONS) == len(set(SECURITY_CHECK_FUNCTIONS))


def _ret_expr_rewriter() -> RetExprRewriter:
    """RetExprRewriter._flatten_locs is purely structural: it doesn't read
    self at all. We can construct a bare instance via __new__."""
    return object.__new__(RetExprRewriter)


def test_ret_expr_flatten_locs_returns_singleton_for_simple_reg_arg():
    rewriter = _ret_expr_rewriter()
    reg = SimRegArg("rax", 8)
    assert rewriter._flatten_locs(reg) == [reg]


def test_ret_expr_flatten_locs_unfolds_struct_arg_into_underlying_regs():
    rewriter = _ret_expr_rewriter()
    rax = SimRegArg("rax", 8)
    rdx = SimRegArg("rdx", 8)
    struct_arg = SimStructArg(_two_field_struct(), {"a": rax, "b": rdx})
    flattened = rewriter._flatten_locs(struct_arg)
    assert flattened == [rax, rdx]


def test_ret_expr_flatten_locs_recurses_through_nested_struct_args():
    rewriter = _ret_expr_rewriter()
    rax = SimRegArg("rax", 8)
    rdx = SimRegArg("rdx", 8)
    rcx = SimRegArg("rcx", 8)
    inner_struct = SimStructArg(_two_field_struct("Inner"), {"a": rax, "b": rdx})
    outer_struct = SimStructArg(_two_field_struct("Outer"), {"a": inner_struct, "b": rcx})
    flattened = rewriter._flatten_locs(outer_struct)
    assert flattened == [rax, rdx, rcx]
