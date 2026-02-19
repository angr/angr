#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment import Expr
from angr.analyses.decompiler.ccall_rewriters.arm_ccalls import ARMCCallRewriter
from angr.engines.vex.claripy.ccall import (
    ARMCondAL,
    ARMCondEQ,
    ARMCondGE,
    ARMCondGT,
    ARMCondHI,
    ARMCondHS,
    ARMCondLE,
    ARMCondLO,
    ARMCondLS,
    ARMCondLT,
    ARMCondMI,
    ARMCondNE,
    ARMCondNV,
    ARMCondPL,
    ARMG_CC_OP_ADD,
    ARMG_CC_OP_LOGIC,
    ARMG_CC_OP_MUL,
    ARMG_CC_OP_SBB,
    ARMG_CC_OP_SUB,
)


def _make_ccall(callee, cond_n_op_val, dep1=None, dep2=None, dep3=None, bits=32):
    """Helper to build a VEXCCallExpression for armg_calculate_condition."""
    cond_n_op = Expr.Const(None, None, cond_n_op_val, 32)
    if dep1 is None:
        dep1 = Expr.Register(None, None, 0, 32)  # r0
    if dep2 is None:
        dep2 = Expr.Register(None, None, 4, 32)  # r1
    if dep3 is None:
        dep3 = Expr.Const(None, None, 0, 32)
    return Expr.VEXCCallExpression(
        idx=0,
        callee=callee,
        operands=(cond_n_op, dep1, dep2, dep3),
        bits=bits,
    )


def _make_flag_ccall(callee, cc_op_val, dep1=None, dep2=None, dep3=None, bits=32):
    """Helper to build a VEXCCallExpression for armg_calculate_flag_*."""
    cc_op = Expr.Const(None, None, cc_op_val, 32)
    if dep1 is None:
        dep1 = Expr.Register(None, None, 0, 32)
    if dep2 is None:
        dep2 = Expr.Register(None, None, 4, 32)
    if dep3 is None:
        dep3 = Expr.Const(None, None, 0, 32)
    return Expr.VEXCCallExpression(
        idx=0,
        callee=callee,
        operands=(cc_op, dep1, dep2, dep3),
        bits=bits,
    )


def _cond_n_op(cond, op):
    return (cond << 4) | op


def _rewrite(ccall):
    p = angr.load_shellcode(b"\x00", arch="ARMEL")
    rw = ARMCCallRewriter(ccall, p)
    return rw.result


def _unwrap_convert(expr):
    """Strip outer Convert wrapper if present, return inner BinaryOp."""
    if isinstance(expr, Expr.Convert):
        return expr.operand
    return expr


class TestARMCCallRewriterCondition(unittest.TestCase):
    """Tests for armg_calculate_condition rewriting."""

    # ---- AL / NV ----

    def test_al_returns_const_1(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondAL, ARMG_CC_OP_SUB))
        result = _rewrite(ccall)
        assert isinstance(result, Expr.Const)
        assert result.value_int == 1

    def test_nv_returns_const_0(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondNV, ARMG_CC_OP_SUB))
        result = _rewrite(ccall)
        assert isinstance(result, Expr.Const)
        assert result.value_int == 0

    # ---- SUB (CMP) conditions ----

    def test_sub_eq(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"

    def test_sub_ne(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondNE, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpNE"

    def test_sub_hs(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"
        assert result.signed is False

    def test_sub_lo(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLO, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is False

    def test_sub_mi(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondMI, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True

    def test_sub_pl(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondPL, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"
        assert result.signed is True

    def test_sub_hi(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHI, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGT"
        assert result.signed is False

    def test_sub_ls(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLS, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLE"
        assert result.signed is False

    def test_sub_ge(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondGE, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"
        assert result.signed is True

    def test_sub_lt(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLT, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True

    def test_sub_gt(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondGT, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGT"
        assert result.signed is True

    def test_sub_le(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLE, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLE"
        assert result.signed is True

    # ---- ADD (CMN) conditions ----

    def test_add_eq(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_ADD))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"
        # operand[0] should be an Add expression
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Add"

    def test_add_ne(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondNE, ARMG_CC_OP_ADD))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpNE"

    def test_add_mi(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondMI, ARMG_CC_OP_ADD))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True

    def test_add_pl(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondPL, ARMG_CC_OP_ADD))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"
        assert result.signed is True

    def test_add_unsupported_returns_none(self):
        # HS on ADD is not implemented
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_ADD))
        result = _rewrite(ccall)
        assert result is None

    # ---- LOGIC conditions ----

    def test_logic_eq(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_LOGIC))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"
        # operand[1] should be Const(0)
        assert isinstance(result.operands[1], Expr.Const) and result.operands[1].value_int == 0

    def test_logic_ne(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondNE, ARMG_CC_OP_LOGIC))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpNE"

    def test_logic_mi(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondMI, ARMG_CC_OP_LOGIC))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True

    def test_logic_unsupported_returns_none(self):
        # HS on LOGIC is not implemented
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_LOGIC))
        result = _rewrite(ccall)
        assert result is None

    # ---- MUL conditions (same as LOGIC) ----

    def test_mul_eq(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_MUL))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"

    def test_mul_mi(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondMI, ARMG_CC_OP_MUL))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True

    # ---- SBB conditions ----

    def test_sbb_hs_no_borrow(self):
        dep3 = Expr.Const(None, None, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"

    def test_sbb_hs_with_borrow(self):
        dep3 = Expr.Const(None, None, 1, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGT"

    def test_sbb_lo_no_borrow(self):
        dep3 = Expr.Const(None, None, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLO, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"

    def test_sbb_unsupported_returns_none(self):
        # EQ on SBB is not implemented
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SBB))
        result = _rewrite(ccall)
        assert result is None

    # ---- Non-const cond_n_op returns None ----

    def test_symbolic_cond_n_op_returns_none(self):
        cond_n_op = Expr.Register(None, None, 0, 32)  # symbolic
        dep1 = Expr.Register(None, None, 0, 32)
        dep2 = Expr.Register(None, None, 4, 32)
        dep3 = Expr.Const(None, None, 0, 32)
        ccall = Expr.VEXCCallExpression(
            idx=0,
            callee="armg_calculate_condition",
            operands=(cond_n_op, dep1, dep2, dep3),
            bits=32,
        )
        result = _rewrite(ccall)
        assert result is None

    # ---- Convert wrapping ----

    def test_result_is_convert_wrapped_to_ccall_bits(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB), bits=32)
        result = _rewrite(ccall)
        assert isinstance(result, Expr.Convert)
        assert result.to_bits == 32


class TestARMCCallRewriterFlagHelpers(unittest.TestCase):
    """Tests for individual flag helper rewriting (flag_c, flag_n, flag_z)."""

    # ---- flag_c ----

    def test_flag_c_sub(self):
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_SUB)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"
        assert result.signed is False

    def test_flag_c_add(self):
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_ADD)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        # The inner operand should be an Add
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Add"

    def test_flag_c_sbb_no_borrow(self):
        dep3 = Expr.Const(None, None, 0, 32)
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_SBB, dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"

    def test_flag_c_sbb_with_borrow(self):
        dep3 = Expr.Const(None, None, 1, 32)
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_SBB, dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGT"

    def test_flag_c_logic_returns_dep2(self):
        dep2 = Expr.Register(None, None, 4, 32)
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_LOGIC, dep2=dep2)
        result = _rewrite(ccall)
        # Should return dep2 directly (shifter carry out)
        assert result is dep2

    def test_flag_c_unknown_op_returns_none(self):
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_MUL)
        result = _rewrite(ccall)
        assert result is None

    def test_flag_c_symbolic_op_returns_none(self):
        cc_op = Expr.Register(None, None, 0, 32)
        dep1 = Expr.Register(None, None, 0, 32)
        dep2 = Expr.Register(None, None, 4, 32)
        dep3 = Expr.Const(None, None, 0, 32)
        ccall = Expr.VEXCCallExpression(
            idx=0, callee="armg_calculate_flag_c", operands=(cc_op, dep1, dep2, dep3), bits=32
        )
        result = _rewrite(ccall)
        assert result is None

    # ---- flag_n ----

    def test_flag_n_sub(self):
        ccall = _make_flag_ccall("armg_calculate_flag_n", ARMG_CC_OP_SUB)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True

    def test_flag_n_add(self):
        ccall = _make_flag_ccall("armg_calculate_flag_n", ARMG_CC_OP_ADD)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True
        # Inner should be Add expression compared against 0
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Add"

    def test_flag_n_logic(self):
        ccall = _make_flag_ccall("armg_calculate_flag_n", ARMG_CC_OP_LOGIC)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True

    def test_flag_n_mul(self):
        ccall = _make_flag_ccall("armg_calculate_flag_n", ARMG_CC_OP_MUL)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True

    # ---- flag_z ----

    def test_flag_z_sub(self):
        ccall = _make_flag_ccall("armg_calculate_flag_z", ARMG_CC_OP_SUB)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"

    def test_flag_z_add(self):
        ccall = _make_flag_ccall("armg_calculate_flag_z", ARMG_CC_OP_ADD)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Add"

    def test_flag_z_logic(self):
        ccall = _make_flag_ccall("armg_calculate_flag_z", ARMG_CC_OP_LOGIC)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"
        assert isinstance(result.operands[1], Expr.Const) and result.operands[1].value_int == 0

    def test_flag_z_mul(self):
        ccall = _make_flag_ccall("armg_calculate_flag_z", ARMG_CC_OP_MUL)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"


class TestARMCCallRewriterRenamedCCall(unittest.TestCase):
    """Tests for _ccall (renamed) expression rewriting."""

    def test_renamed_ccall_rewritten_as_condition(self):
        # A _ccall with valid cond_n_op should be rewritten the same as armg_calculate_condition
        ccall = _make_ccall("_ccall", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"

    def test_renamed_ccall_invalid_op_returns_none(self):
        # cond_n_op with invalid cc_op (0xFF) should return None
        ccall = _make_ccall("_ccall", _cond_n_op(ARMCondEQ, 0xF))
        result = _rewrite(ccall)
        assert result is None

    def test_renamed_ccall_wrong_operand_count_not_rewritten(self):
        # A _ccall with != 4 operands should not be rewritten
        cond_n_op = Expr.Const(None, None, _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB), 32)
        dep1 = Expr.Register(None, None, 0, 32)
        ccall = Expr.VEXCCallExpression(idx=0, callee="_ccall", operands=(cond_n_op, dep1), bits=32)
        result = _rewrite(ccall)
        assert result is None

    def test_unrelated_callee_returns_none(self):
        # A callee name that is neither armg_calculate_* nor _ccall should return None
        ccall = _make_ccall("some_other_function", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB))
        result = _rewrite(ccall)
        assert result is None


if __name__ == "__main__":
    unittest.main()
