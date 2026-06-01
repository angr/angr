#!/usr/bin/env python3
"""Unit tests for the Rust outliner optimization passes.

Each outliner registers as a full ``OptimizationPass`` and runs against a real
``Project``/graph during decompilation, so end-to-end behaviour is covered by the
integration tests in ``test_rust_decompiler.py``. The tests here focus on the
outliners' *pure* helpers — the predicates and decoders that decide whether a
given AIL fragment matches the outline-able shape — by constructing small AIL
expressions directly and calling the helpers without booting an analysis.

Outliners whose entire logic lives inside an ``_analyze`` closure that references
``self.project``/``self.kb`` (``string_outliner``, ``vec_outliner``,
``string_literal_outliner``) have no extractable pure helper to unit-test in
isolation; their behaviour is exercised only by the integration tests.
"""

from __future__ import annotations

import angr
from angr.ailment import Block
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Load,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import ConditionalJump
from angr.rust.optimization_passes.outliners.string_cmp_outliner import StringCmpOutliner
from angr.rust.optimization_passes.outliners.unwrap_outliner import (
    OPTION_UNWRAP_FAILED_FUNCTION,
    RESULT_UNWRAP_FAILED_FUNCTION,
    UNWRAP_FAILED_FUNCTIONS,
    UNWRAP_FUNCTIONS,
    UnwrapOutliner,
    UnwrapSimplifierState,
)


def _string_cmp_outliner() -> StringCmpOutliner:
    """Build a StringCmpOutliner without invoking its full ``__init__``.

    The outliner inherits from ``OptimizationPass`` whose constructor expects a
    real angr ``Function``/manager; we only need the inner ``_extract_cmp`` /
    ``_extract_cmps`` / ``_try_decode_str`` helpers, which read ``self.project``
    (forwarded through ``self._func.project``).
    """
    project = angr.load_shellcode(b"\x90", arch="amd64")
    func = project.kb.functions.function(addr=0x0, name="dummy", create=True)
    outliner = object.__new__(StringCmpOutliner)
    outliner._func = func  # pyright: ignore[reportAttributeAccessIssue]
    return outliner


def _const(value: int, bits: int = 64) -> Const:
    return Const(0, None, value, bits)


def _load(addr_expr, bits: int = 64) -> Load:
    return Load(0, addr_expr, bits // 8, "Iend_LE")


def _stack_vvar(varid: int = 0, bits: int = 64) -> VirtualVariable:
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.STACK, oident=0x10)


def test_string_cmp_try_decode_str_decodes_printable_ascii():
    outliner = _string_cmp_outliner()
    # "abcd" little-endian as a 32-bit word: 0x64636261.
    assert outliner._try_decode_str(0x64636261, 4) == "abcd"


def test_string_cmp_try_decode_str_rejects_non_utf8_bytes():
    outliner = _string_cmp_outliner()
    # 0xFF is a lone continuation byte — not valid UTF-8.
    assert outliner._try_decode_str(0xFF, 1) is None


def test_string_cmp_try_decode_str_rejects_unprintable_after_whitespace_strip():
    outliner = _string_cmp_outliner()
    # 0x01 is a control char, not whitespace, so it must be rejected.
    assert outliner._try_decode_str(0x01, 1) is None


def test_string_cmp_extract_cmp_recognizes_load_eq_const_pattern():
    outliner = _string_cmp_outliner()
    # ((Load(addr=str_var)) == 0x64636261) ⇒ str_var, offset 0, "abcd".
    str_var = _stack_vvar()
    cmp_expr = BinaryOp(0, "CmpEQ", [_load(str_var, bits=32), _const(0x64636261, bits=32)])
    result = outliner._extract_cmp(cmp_expr)
    assert result is not None
    extracted_var, offset, decoded = result
    assert extracted_var is str_var
    assert offset == 0
    assert decoded == "abcd"


def test_string_cmp_extract_cmp_extracts_offset_from_load_with_constant_addend():
    outliner = _string_cmp_outliner()
    str_var = _stack_vvar()
    addr = BinaryOp(0, "Add", [str_var, _const(8)])
    cmp_expr = BinaryOp(0, "CmpEQ", [_load(addr, bits=32), _const(0x64636261, bits=32)])
    result = outliner._extract_cmp(cmp_expr)
    assert result is not None
    _, offset, decoded = result
    assert offset == 8
    assert decoded == "abcd"


def test_string_cmp_extract_cmp_returns_none_for_non_cmpeq_op():
    outliner = _string_cmp_outliner()
    str_var = _stack_vvar()
    bogus = BinaryOp(0, "Add", [_load(str_var, bits=32), _const(1, bits=32)])
    assert outliner._extract_cmp(bogus) is None


def test_string_cmp_extract_cmps_collapses_logical_and_chain():
    outliner = _string_cmp_outliner()
    str_var = _stack_vvar()
    # Two adjacent four-byte compares AND-ed together: "abcd" then "efgh".
    cmp_a = BinaryOp(0, "CmpEQ", [_load(str_var, bits=32), _const(0x64636261, bits=32)])
    addr_b = BinaryOp(0, "Add", [str_var, _const(4)])
    cmp_b = BinaryOp(0, "CmpEQ", [_load(addr_b, bits=32), _const(0x68676665, bits=32)])
    chain = BinaryOp(0, "LogicalAnd", [cmp_a, cmp_b])

    result = outliner._extract_cmps(chain)
    assert result is not None
    assert len(result) == 2
    decoded_strs = sorted(t[2] for t in result)
    assert decoded_strs == ["abcd", "efgh"]


def test_string_cmp_extract_cmps_returns_none_when_any_arm_unrecognized():
    outliner = _string_cmp_outliner()
    str_var = _stack_vvar()
    cmp_ok = BinaryOp(0, "CmpEQ", [_load(str_var, bits=32), _const(0x64636261, bits=32)])
    bogus = BinaryOp(0, "Sub", [_load(str_var, bits=32), _const(1, bits=32)])
    chain = BinaryOp(0, "LogicalAnd", [cmp_ok, bogus])
    assert outliner._extract_cmps(chain) is None


def test_string_cmp_extract_cmp_handles_xor_against_zero_intermediate():
    outliner = _string_cmp_outliner()
    str_var = _stack_vvar()
    inner_xor = BinaryOp(0, "Xor", [_load(str_var, bits=32), _const(0x64636261, bits=32)])
    cmp_expr = BinaryOp(0, "CmpEQ", [inner_xor, _const(0, bits=32)])
    result = outliner._extract_cmp(cmp_expr)
    assert result is not None
    _, _, decoded = result
    assert decoded == "abcd"


def test_string_cmp_extract_cmp_unwraps_convert_node():
    outliner = _string_cmp_outliner()
    str_var = _stack_vvar()
    converted = Convert(0, 32, 32, False, _load(str_var, bits=32))
    cmp_expr = BinaryOp(0, "CmpEQ", [converted, _const(0x64636261, bits=32)])
    result = outliner._extract_cmp(cmp_expr)
    assert result is not None


def test_unwrap_outliner_constants_are_distinct_and_paired():
    # Sanity guards: the FAILED → success-name table must cover every advertised
    # FAILED function and have no accidental aliasing.
    assert RESULT_UNWRAP_FAILED_FUNCTION != OPTION_UNWRAP_FAILED_FUNCTION
    assert set(UNWRAP_FAILED_FUNCTIONS) == {
        RESULT_UNWRAP_FAILED_FUNCTION,
        OPTION_UNWRAP_FAILED_FUNCTION,
    }
    assert set(UNWRAP_FUNCTIONS.keys()) == set(UNWRAP_FAILED_FUNCTIONS)
    assert UNWRAP_FUNCTIONS[RESULT_UNWRAP_FAILED_FUNCTION].endswith("::unwrap")
    assert UNWRAP_FUNCTIONS[OPTION_UNWRAP_FAILED_FUNCTION].endswith("::unwrap")


def test_unwrap_extract_vvar_from_cond_returns_vvar_for_direct_operand():
    vvar = _stack_vvar()
    cond = BinaryOp(0, "CmpEQ", [vvar, _const(0)])
    assert UnwrapOutliner._extract_vvar_from_cond(cond) is vvar


def test_unwrap_extract_vvar_from_cond_unwraps_load_of_stack_reference():
    # Load(addr=&stack_vvar) ⇒ underlying stack vvar.
    vvar = _stack_vvar()
    cond = BinaryOp(0, "CmpEQ", [_load(UnaryOp(0, "Reference", vvar)), _const(0)])
    assert UnwrapOutliner._extract_vvar_from_cond(cond) is vvar


def test_unwrap_extract_vvar_from_cond_returns_none_for_unrecognized_operand():
    cond = BinaryOp(0, "CmpEQ", [_const(0), _const(1)])
    assert UnwrapOutliner._extract_vvar_from_cond(cond) is None


def test_unwrap_state_decides_eq_discriminant_when_true_target_matches_failed_block():
    # ConditionalJump: cond == discriminant ⇒ jump-to-failed-block.
    vvar = _stack_vvar()
    cond = BinaryOp(0, "CmpEQ", [vvar, _const(7)])
    failed_block = Block(0x4000, 0, statements=[], idx=0)
    jump = ConditionalJump(
        0,
        cond,
        Const(0, None, 0x4000, 64),
        Const(0, None, 0x5000, 64),
        true_target_idx=0,
        false_target_idx=0,
    )
    cond_block = Block(0x3000, 0, statements=[jump], idx=0)

    state = UnwrapSimplifierState(
        conditional_jump_block=cond_block,
        unwrap_failed_block=failed_block,
        ownership_move_block=None,
        cmp_expr=cond,
        unwrap_failed_func_name=RESULT_UNWRAP_FAILED_FUNCTION,
    )
    assert state.err_or_none_discriminant == 7


def test_unwrap_state_decides_ne_discriminant_when_false_target_matches_failed_block():
    vvar = _stack_vvar()
    cond = BinaryOp(0, "CmpNE", [vvar, _const(0)])
    failed_block = Block(0x4000, 0, statements=[], idx=0)
    jump = ConditionalJump(
        0,
        cond,
        Const(0, None, 0x5000, 64),
        Const(0, None, 0x4000, 64),
        true_target_idx=0,
        false_target_idx=0,
    )
    cond_block = Block(0x3000, 0, statements=[jump], idx=0)

    state = UnwrapSimplifierState(
        conditional_jump_block=cond_block,
        unwrap_failed_block=failed_block,
        ownership_move_block=None,
        cmp_expr=cond,
        unwrap_failed_func_name=OPTION_UNWRAP_FAILED_FUNCTION,
    )
    assert state.err_or_none_discriminant == 0


def test_unwrap_state_returns_none_for_non_binary_condition():
    vvar = _stack_vvar()
    failed_block = Block(0x4000, 0, statements=[], idx=0)
    jump = ConditionalJump(
        0, vvar, Const(0, None, 0x4000, 64), Const(0, None, 0x5000, 64), true_target_idx=0, false_target_idx=0
    )
    cond_block = Block(0x3000, 0, statements=[jump], idx=0)
    state = UnwrapSimplifierState(
        conditional_jump_block=cond_block,
        unwrap_failed_block=failed_block,
        ownership_move_block=None,
        cmp_expr=None,
        unwrap_failed_func_name=RESULT_UNWRAP_FAILED_FUNCTION,
    )
    assert state.err_or_none_discriminant is None
