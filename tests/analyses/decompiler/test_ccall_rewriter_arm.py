#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr.ailment import Expr, Manager
from angr.analyses.decompiler.ccall_rewriters.arm_ccalls import ARMCCallRewriter
from angr.engines.vex.claripy.ccall import (
    ARMG_CC_OP_ADC,
    ARMG_CC_OP_ADD,
    ARMG_CC_OP_COPY,
    ARMG_CC_OP_LOGIC,
    ARMG_CC_OP_MUL,
    ARMG_CC_OP_SBB,
    ARMG_CC_OP_SUB,
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
    ARMCondVS,
)
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


def _make_ccall(callee, cond_n_op_val, dep1=None, dep2=None, dep3=None, bits=32, **tags):
    """Helper to build a VEXCCallExpression for armg_calculate_condition."""
    cond_n_op = Expr.Const(0, cond_n_op_val, 32)
    if dep1 is None:
        dep1 = Expr.Register(1, 0, 32)  # r0
    if dep2 is None:
        dep2 = Expr.Register(2, 4, 32)  # r1
    if dep3 is None:
        dep3 = Expr.Const(3, 0, 32)
    return Expr.VEXCCallExpression(
        idx=0,
        callee=callee,
        operands=(cond_n_op, dep1, dep2, dep3),
        bits=bits,
        **tags,
    )


def _make_flag_ccall(callee, cc_op_val, dep1=None, dep2=None, dep3=None, bits=32):
    """Helper to build a VEXCCallExpression for armg_calculate_flag_*."""
    cc_op = Expr.Const(0, cc_op_val, 32)
    if dep1 is None:
        dep1 = Expr.Register(1, 0, 32)
    if dep2 is None:
        dep2 = Expr.Register(2, 4, 32)
    if dep3 is None:
        dep3 = Expr.Const(3, 0, 32)
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
    rw = ARMCCallRewriter(ccall, p, Manager())
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

    def test_add_hs_is_carry(self):
        # C = (dep1 + dep2) <u dep1
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_ADD))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is False
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Add"
        assert result.operands[1].likes(ccall.operands[1])

    def test_add_hi_is_carry_and_nonzero(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHI, ARMG_CC_OP_ADD))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "LogicalAnd"
        assert result.operands[0].op == "CmpLT" and result.operands[1].op == "CmpNE"

    def test_add_ge_nonconst_returns_none(self):
        # N == V of dep1 + dep2 is not a 32-bit comparison
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondGE, ARMG_CC_OP_ADD))
        assert _rewrite(ccall) is None

    def test_add_const_unsigned(self):
        # cmn r0, #5; bhs  ==>  r0 >=u -5
        dep2 = Expr.Const(2, 5, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_ADD), dep2=dep2)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"
        assert result.signed is False
        assert isinstance(result.operands[1], Expr.Const) and result.operands[1].value_int == (-5) & 0xFFFFFFFF

    def test_add_const_signed(self):
        # cmn r0, #0x8000; blt  ==>  r0 <s -0x8000
        dep2 = Expr.Const(2, 0x8000, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLT, ARMG_CC_OP_ADD), dep2=dep2)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT"
        assert result.signed is True
        assert isinstance(result.operands[1], Expr.Const) and result.operands[1].value_int == (-0x8000) & 0xFFFFFFFF

    def test_add_const_int_min_signed_returns_none(self):
        dep2 = Expr.Const(2, 0x80000000, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondGE, ARMG_CC_OP_ADD), dep2=dep2)
        assert _rewrite(ccall) is None

    def test_add_const_zero_unsigned_returns_none(self):
        dep2 = Expr.Const(2, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_ADD), dep2=dep2)
        assert _rewrite(ccall) is None

    def test_add_const_mi_keeps_sum(self):
        # the sign of dep1 + c is not dep1 <s -c (overflow)
        dep2 = Expr.Const(2, 1, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondMI, ARMG_CC_OP_ADD), dep2=dep2)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT" and result.signed is True
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Add"

    def test_adc_without_carry_is_add(self):
        ccall = _make_ccall(
            "armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_ADC), dep3=Expr.Const(3, 0, 32)
        )
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Add"

    def test_adc_symbolic_carry_eq(self):
        # Z only depends on dep1 + dep2 + carry
        dep3 = Expr.Register(3, 8, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_ADC), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"
        res = result.operands[0]
        assert isinstance(res, Expr.BinaryOp) and res.op == "Add" and res.operands[1].likes(dep3)
        assert isinstance(res.operands[0], Expr.BinaryOp) and res.operands[0].op == "Add"

    def test_adc_symbolic_carry_hs_returns_none(self):
        dep3 = Expr.Register(3, 8, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_ADC), dep3=dep3)
        assert _rewrite(ccall) is None

    def test_sbb_symbolic_carry_mi(self):
        # N is the sign of dep1 - dep2 - (carry ^ 1)
        dep3 = Expr.Register(3, 8, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondMI, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT" and result.signed is True
        res = result.operands[0]
        assert isinstance(res, Expr.BinaryOp) and res.op == "Sub"
        assert isinstance(res.operands[1], Expr.BinaryOp) and res.operands[1].op == "Xor"

    # ---- SUB: N flag is the sign of the difference ----

    def test_sub_mi_is_sign_of_difference(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondMI, ARMG_CC_OP_SUB))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT" and result.signed is True
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Sub"
        assert isinstance(result.operands[1], Expr.Const) and result.operands[1].value_int == 0

    def test_sub_pl_against_zero(self):
        dep2 = Expr.Const(2, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondPL, ARMG_CC_OP_SUB), dep2=dep2)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE" and result.signed is True
        assert result.operands[0].likes(ccall.operands[1])

    # ---- COPY (NZCV in dep1[31:28]) ----

    def test_copy_eq_tests_z_bit(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_COPY))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpNE"
        mask = result.operands[0]
        assert isinstance(mask, Expr.BinaryOp) and mask.op == "And"
        assert isinstance(mask.operands[1], Expr.Const) and mask.operands[1].value_int == 1 << 30

    def test_copy_vs_tests_v_bit(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondVS, ARMG_CC_OP_COPY))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpNE"
        assert result.operands[0].operands[1].value_int == 1 << 28

    def test_copy_lt_is_n_xor_v(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLT, ARMG_CC_OP_COPY))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpNE"
        mask = result.operands[0]
        assert isinstance(mask, Expr.BinaryOp) and mask.op == "And" and mask.operands[1].value_int == 1 << 28
        assert isinstance(mask.operands[0], Expr.BinaryOp) and mask.operands[0].op == "Xor"

    def test_copy_gt_is_not_z_and_n_eq_v(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondGT, ARMG_CC_OP_COPY))
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "LogicalAnd"
        assert result.operands[0].op == "CmpEQ" and result.operands[1].op == "CmpEQ"

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

    def test_logic_hs_is_shifter_carry(self):
        dep2 = Expr.Register(2, 4, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_LOGIC), dep2=dep2)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpNE"
        assert result.operands[0].likes(dep2)
        assert isinstance(result.operands[1], Expr.Const) and result.operands[1].value_int == 0

    def test_logic_ge_returns_none(self):
        # N == V with V being the stale dep3 is not a comparison
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondGE, ARMG_CC_OP_LOGIC))
        assert _rewrite(ccall) is None

    def test_mul_hs_returns_none(self):
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_MUL))
        assert _rewrite(ccall) is None

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

    # dep3 is the old C flag: C=1 means no borrow (dep1 - dep2), C=0 means dep1 - dep2 - 1

    def test_sbb_hs_no_borrow_is_sub(self):
        dep3 = Expr.Const(0, 1, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE" and result.signed is False

    def test_sbb_hs_with_borrow(self):
        dep3 = Expr.Const(0, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGT" and result.signed is False

    def test_sbb_lo_with_borrow(self):
        dep3 = Expr.Const(0, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLO, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLE" and result.signed is False

    def test_sbb_lt_no_borrow_is_signed_sub(self):
        dep3 = Expr.Const(0, 1, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLT, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT" and result.signed is True

    def test_sbb_eq_with_borrow(self):
        # dep1 - dep2 - 1 == 0  ==>  dep1 == dep2 + 1
        dep3 = Expr.Const(0, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"
        assert isinstance(result.operands[1], Expr.BinaryOp) and result.operands[1].op == "Add"

    def test_sbb_lt_with_borrow_returns_none(self):
        dep3 = Expr.Const(0, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondLT, ARMG_CC_OP_SBB), dep3=dep3)
        assert _rewrite(ccall) is None

    def test_sbb_mi_with_borrow_is_sign_of_result(self):
        dep3 = Expr.Const(0, 0, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondMI, ARMG_CC_OP_SBB), dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT" and result.signed is True
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Sub"

    def test_sbb_symbolic_carry_returns_none(self):
        dep3 = Expr.Register(3, 8, 32)
        ccall = _make_ccall("armg_calculate_condition", _cond_n_op(ARMCondHS, ARMG_CC_OP_SBB), dep3=dep3)
        assert _rewrite(ccall) is None

    # ---- Non-const cond_n_op returns None ----

    def test_symbolic_cond_n_op_returns_none(self):
        cond_n_op = Expr.Register(0, 0, 32)  # symbolic
        dep1 = Expr.Register(1, 0, 32)
        dep2 = Expr.Register(2, 4, 32)
        dep3 = Expr.Const(3, 0, 32)
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
        dep3 = Expr.Const(0, 1, 32)
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_SBB, dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE"

    def test_flag_c_sbb_with_borrow(self):
        dep3 = Expr.Const(0, 0, 32)
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_SBB, dep3=dep3)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGT"

    def test_flag_c_sbb_symbolic_carry_returns_none(self):
        dep3 = Expr.Register(3, 8, 32)
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_SBB, dep3=dep3)
        assert _rewrite(ccall) is None

    def test_flag_c_logic_returns_dep2(self):
        dep2 = Expr.Register(0, 4, 32)
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_LOGIC, dep2=dep2)
        result = _rewrite(ccall)
        # Should return dep2 directly (shifter carry out).
        assert result is not None and result.likes(dep2)

    def test_flag_c_mul_is_dep3_bit1(self):
        ccall = _make_flag_ccall("armg_calculate_flag_c", ARMG_CC_OP_MUL)
        result = _rewrite(ccall)
        assert isinstance(result, Expr.BinaryOp) and result.op == "And" and result.bits == 32
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Shr"

    def test_flag_c_unknown_op_returns_none(self):
        ccall = _make_flag_ccall("armg_calculate_flag_c", 0xF)
        result = _rewrite(ccall)
        assert result is None

    def test_flag_n_sub_is_sign_of_difference(self):
        ccall = _make_flag_ccall("armg_calculate_flag_n", ARMG_CC_OP_SUB)
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpLT" and result.signed is True
        assert isinstance(result.operands[0], Expr.BinaryOp) and result.operands[0].op == "Sub"

    def test_flag_v_sub(self):
        # V = ((dep1 ^ dep2) & (dep1 ^ (dep1 - dep2))) >> 31
        ccall = _make_flag_ccall("armg_calculate_flag_v", ARMG_CC_OP_SUB)
        result = _rewrite(ccall)
        assert isinstance(result, Expr.BinaryOp) and result.op == "Shr" and result.bits == 32
        assert isinstance(result.operands[1], Expr.Const) and result.operands[1].value_int == 31
        inner = result.operands[0]
        assert isinstance(inner, Expr.BinaryOp) and inner.op == "And"
        assert all(isinstance(o, Expr.BinaryOp) and o.op == "Xor" for o in inner.operands)

    def test_flag_v_logic_is_dep3(self):
        dep3 = Expr.Register(3, 8, 32)
        ccall = _make_flag_ccall("armg_calculate_flag_v", ARMG_CC_OP_LOGIC, dep3=dep3)
        result = _rewrite(ccall)
        assert result is not None and result.likes(dep3)

    def test_flag_c_symbolic_op_returns_none(self):
        cc_op = Expr.Register(0, 0, 32)
        dep1 = Expr.Register(1, 0, 32)
        dep2 = Expr.Register(2, 4, 32)
        dep3 = Expr.Const(3, 0, 32)
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
        # the rename keeps the original callee in the vex_callee tag
        ccall = _make_ccall("_ccall", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB), vex_callee="armg_calculate_condition")
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"

    def test_renamed_flag_ccall_not_misread_as_condition(self):
        # flag_c(SUB, ...) has the same operand shape as condition(EQ|SUB, ...) but means dep1 >=u dep2
        ccall = _make_ccall("_ccall", ARMG_CC_OP_SUB, vex_callee="armg_calculate_flag_c")
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpGE" and result.signed is False

    def test_renamed_ccall_without_callee_tag_returns_none(self):
        ccall = _make_ccall("_ccall", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB))
        assert _rewrite(ccall) is None

    def test_rename_keeps_original_callee(self):
        ccall = Expr.VEXCCallExpression(
            idx=0,
            callee="armg_calculate_condition",
            operands=(Expr.Register(0, 0, 32), Expr.Register(1, 4, 32), Expr.Const(2, 0, 32), Expr.Const(3, 0, 32)),
            bits=32,
        )
        p = angr.load_shellcode(b"\x00", arch="ARMEL")
        result = ARMCCallRewriter(ccall, p, Manager(), rename_ccalls=True).result
        assert isinstance(result, Expr.VEXCCallExpression)
        assert result.callee == "_ccall" and result.tags["vex_callee"] == "armg_calculate_condition"

    def test_renamed_ccall_invalid_op_returns_none(self):
        # cond_n_op with invalid cc_op (0xF) should return None
        ccall = _make_ccall("_ccall", _cond_n_op(ARMCondEQ, 0xF), vex_callee="armg_calculate_condition")
        result = _rewrite(ccall)
        assert result is None

    def test_renamed_ccall_wrong_operand_count_not_rewritten(self):
        # A _ccall with != 4 operands should not be rewritten
        cond_n_op = Expr.Const(0, _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB), 32)
        dep1 = Expr.Register(1, 0, 32)
        ccall = Expr.VEXCCallExpression(idx=0, callee="_ccall", operands=(cond_n_op, dep1), bits=32)
        result = _rewrite(ccall)
        assert result is None

    def test_unrelated_callee_returns_none(self):
        # A callee name that is neither armg_calculate_* nor _ccall should return None
        ccall = _make_ccall("some_other_function", _cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB))
        result = _rewrite(ccall)
        assert result is None


class TestARMCCallRewritingOnBinaries(unittest.TestCase):
    """Decompile small real functions whose flag-setting and flag-using instructions sit in different blocks."""

    @staticmethod
    def _decompile(rel_path: str, addr: int) -> str:
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, rel_path),
            addr,
            project_kwargs={"auto_load_libs": False},
            cfg_kwargs={"normalize": True, "data_references": True},
            run_ccc=False,
        )
        dec = proj.analyses.Decompiler(proj.kb.functions[addr], cfg=cfg.model)
        assert dec.codegen is not None
        return dec.codegen.text

    def test_cortexm_cmp_and_branch_in_different_blocks(self):
        # prvSVCHandler: cmp r3, #1 ... blo in a later block (LO | SUB)
        text = self._decompile("armel/RTOSDemo.axf.issue_685", 0x1335)
        assert "armg_calculate" not in text and "_ccall(" not in text
        assert re.search(r"\bv\d+ (>=|<) 1\b", text) is not None

    def test_armhf_fp_compare_through_nzcv_copy(self):
        # compare_floats: vcmp / vmrs APSR_nzcv / blt (LT | COPY)
        text = self._decompile("armhf/float_int_conversion.elf", 0x8317)
        assert "armg_calculate" not in text and "_ccall(" not in text

    def test_thumb_itstate_guard_folds_away(self):
        # call_gmon_start starts with a guard ITE(itstate != 0, armg_calculate_condition(...), 1) whose condition
        # is constant-folded; the ccall must not survive as a renamed _ccall
        text = self._decompile("armel/fauxware", 0x84E5)
        assert "armg_calculate" not in text and "_ccall(" not in text


if __name__ == "__main__":
    unittest.main()
