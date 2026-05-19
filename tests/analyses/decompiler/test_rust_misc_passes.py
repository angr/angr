#!/usr/bin/env python3
"""Unit tests for the remaining Rust optimization passes.

Each pass here exposes a small surface — a constant, a static predicate, or
a rewriter that operates on a stub project. End-to-end behaviour is covered
by ``test_rust_decompiler.py``; the goal of these tests is to lock down the
pure pieces so refactors can't silently drift them.

The ``RustCallingConvention`` *optimization pass* (not the same as the
analysis) is a 4-line delegator and is exercised exclusively through
integration tests; nothing in it is unit-testable in isolation.
"""

from __future__ import annotations

import angr

from angr.ailment.expression import (
    Const,
    Load,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)

from angr.rust.optimization_passes.deref_coercion_simplifier import (
    STR_CMP_EQ_FUNCTION,
    STR_CMP_NE_FUNCTION,
)
from angr.rust.optimization_passes.deref_coercion_simplifier_uninlined import (
    DEREF_COERCION_FUNCTIONS,
)
from angr.rust.optimization_passes.str_argument_simplifier import StrArgumentSimplifier
from angr.rust.optimization_passes.struct_return_simplifier import StructReturnSimplifier


def _const(value: int = 0, bits: int = 64) -> Const:
    return Const(0, None, value, bits)


def _stack_vvar(varid: int = 0, bits: int = 64, offset: int = 0x10) -> VirtualVariable:
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.STACK, oident=offset)


# ---------------------------------------------------------------------------
# DerefCoercion constants
# ---------------------------------------------------------------------------


def test_str_cmp_function_constants_are_distinct_and_well_formed():
    # The walker uses these names verbatim against demangled call targets;
    # any drift in their literal value silently disables the rewrite.
    assert STR_CMP_NE_FUNCTION != STR_CMP_EQ_FUNCTION
    assert STR_CMP_NE_FUNCTION.endswith("::ne")
    assert STR_CMP_EQ_FUNCTION.endswith("::eq")
    assert "alloc::string::String" in STR_CMP_NE_FUNCTION
    assert "core::cmp::PartialEq" in STR_CMP_EQ_FUNCTION


def test_deref_coercion_functions_list_covers_both_traits():
    # Both Deref and DerefMut entry points must be present, otherwise the
    # uninlined pass would miss half the call shapes.
    assert "core::ops::deref::Deref::deref" in DEREF_COERCION_FUNCTIONS
    assert "core::ops::deref_mut::DerefMut::deref_mut" in DEREF_COERCION_FUNCTIONS
    assert len(DEREF_COERCION_FUNCTIONS) == len(set(DEREF_COERCION_FUNCTIONS))


# ---------------------------------------------------------------------------
# StrArgumentSimplifier.try_str_literal
# ---------------------------------------------------------------------------


def _str_argument_simplifier() -> StrArgumentSimplifier:
    """Build a StrArgumentSimplifier without invoking its full ``__init__``.

    The ``try_str_literal`` helper only reads ``self.project`` (forwarded via
    ``self._func.project``) for ``arch.bits`` and the section reader.
    """
    project = angr.load_shellcode(b"\x90", arch="amd64")
    func = project.kb.functions.function(addr=0x0, name="dummy", create=True)
    simp = object.__new__(StrArgumentSimplifier)
    simp._func = func  # pyright: ignore[reportAttributeAccessIssue]
    return simp


def test_try_str_literal_returns_none_when_either_arg_is_not_const():
    simp = _str_argument_simplifier()
    assert simp.try_str_literal(_const(0xDEAD), _stack_vvar()) is None
    assert simp.try_str_literal(_stack_vvar(), _const(4)) is None


def test_try_str_literal_returns_none_when_section_lookup_fails():
    # load_shellcode produces a Blob with no sections, so extract_str returns
    # None and try_str_literal must propagate that as None.
    simp = _str_argument_simplifier()
    assert simp.try_str_literal(_const(0xDEAD), _const(4)) is None


# ---------------------------------------------------------------------------
# StructReturnSimplifier._is_stack_mem
# ---------------------------------------------------------------------------


def test_is_stack_mem_extracts_offset_and_size_from_load_at_stack_base():
    load = Load(0, StackBaseOffset(0, 64, -0x20), 8, "Iend_LE")
    offset, size = StructReturnSimplifier._is_stack_mem(load)
    assert offset == -0x20
    assert size == 8


def test_is_stack_mem_extracts_offset_and_size_from_stack_vvar():
    vvar = _stack_vvar(offset=-0x18)
    offset, size = StructReturnSimplifier._is_stack_mem(vvar)
    assert offset == -0x18
    assert size == vvar.size


def test_is_stack_mem_returns_none_pair_for_register_vvar():
    reg_vvar = VirtualVariable(0, 0, 64, VirtualVariableCategory.REGISTER, oident=16)
    offset, size = StructReturnSimplifier._is_stack_mem(reg_vvar)
    assert offset is None
    assert size is None


def test_is_stack_mem_returns_none_pair_for_unrelated_expression():
    offset, size = StructReturnSimplifier._is_stack_mem(_const())
    assert offset is None
    assert size is None


def test_is_stack_mem_returns_none_for_load_with_non_stack_address():
    # Load whose address isn't a StackBaseOffset → predicate must reject.
    bogus_load = Load(0, _const(0xDEADBEEF), 8, "Iend_LE")
    offset, size = StructReturnSimplifier._is_stack_mem(bogus_load)
    assert offset is None
    assert size is None
