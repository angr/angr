from __future__ import annotations

import pytest
import claripy

from angr.ailment import Expr
from angr.analyses.decompiler.ccall_rewriters.amd64_ccalls import (
    AMD64CCallRewriter,
    AMD64_CondTypes,
    AMD64_OpTypes,
)
from angr.analyses.decompiler.ccall_rewriters.arm_ccalls import ARMCCallRewriter
from angr.analyses.decompiler.ccall_rewriters.x86_ccalls import X86CCallRewriter, X86_CondTypes, X86_OpTypes
from angr.ailment.expression import VirtualVariableCategory
from angr.engines.vex.claripy import ccall as ccall_sem
from angr.engines.vex.claripy.ccall import (
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
    ARMCondPL,
    ARMG_CC_OP_ADD,
    ARMG_CC_OP_LOGIC,
    ARMG_CC_OP_SBB,
    ARMG_CC_OP_SUB,
)


def _const(value: int, bits: int) -> Expr.Const:
    return Expr.Const(None, None, value, bits)


def _non_none_int(value: int | None) -> int:
    assert value is not None
    return value


def _cmp_from_result(result: Expr.Expression) -> Expr.BinaryOp:
    assert isinstance(result, Expr.Convert)
    cmp_expr = result.operands[0]
    assert isinstance(cmp_expr, Expr.BinaryOp)
    return cmp_expr


def _arm_cond_n_op(cond: int, op: int) -> int:
    return (cond << 4) | (op & 0xF)


def _vv(varid: int, bits: int) -> Expr.VirtualVariable:
    return Expr.VirtualVariable(None, varid, bits, VirtualVariableCategory.UNKNOWN)


def _ail_to_claripy(
    expr: Expr.Expression, vv_map: dict[int, claripy.ast.BV], mul_signed: bool = False
) -> claripy.ast.BV:
    if isinstance(expr, Expr.Call) and isinstance(expr.target, str):
        assert expr.args is not None
        a = _ail_to_claripy(expr.args[0], vv_map, mul_signed=mul_signed)
        b = _ail_to_claripy(expr.args[1], vv_map, mul_signed=mul_signed)
        n = a.size()
        if expr.target == "__OFADD__":
            ext_a = a.sign_extend(1)
            ext_b = b.sign_extend(1)
            ext_sum = ext_a + ext_b
            trunc = claripy.Extract(n - 1, 0, ext_sum)
            of = claripy.If(ext_sum != trunc.sign_extend(1), claripy.BVV(1, 1), claripy.BVV(0, 1))
            return of.zero_extend(expr.bits - 1) if expr.bits > 1 else of
        if expr.target == "__OFMUL__":
            if mul_signed:
                ext_a = a.sign_extend(n)
                ext_b = b.sign_extend(n)
            else:
                ext_a = a.zero_extend(n)
                ext_b = b.zero_extend(n)
            prod = ext_a * ext_b
            trunc = claripy.Extract(n - 1, 0, prod)
            if mul_signed:
                of = claripy.If(prod != trunc.sign_extend(n), claripy.BVV(1, 1), claripy.BVV(0, 1))
            else:
                of = claripy.If(prod != trunc.zero_extend(n), claripy.BVV(1, 1), claripy.BVV(0, 1))
            return of.zero_extend(expr.bits - 1) if expr.bits > 1 else of
        raise NotImplementedError(f"Unsupported builtin {expr.target}")
    if isinstance(expr, Expr.Const):
        return claripy.BVV(expr.value_int, expr.bits)
    if isinstance(expr, Expr.VirtualVariable):
        return vv_map[expr.varid]
    if isinstance(expr, Expr.Convert):
        v = _ail_to_claripy(expr.operands[0], vv_map, mul_signed=mul_signed)
        from_bits = expr.from_bits
        to_bits = expr.to_bits
        assert from_bits == v.size()
        if to_bits < from_bits:
            return claripy.Extract(to_bits - 1, 0, v)
        if to_bits > from_bits:
            return v.sign_extend(to_bits - from_bits) if expr.is_signed else v.zero_extend(to_bits - from_bits)
        return v
    if isinstance(expr, Expr.ITE):
        cond = _ail_to_claripy(expr.cond, vv_map, mul_signed=mul_signed)
        t = _ail_to_claripy(expr.iftrue, vv_map, mul_signed=mul_signed)
        f = _ail_to_claripy(expr.iffalse, vv_map, mul_signed=mul_signed)
        return claripy.If(cond != 0, t, f)
    if isinstance(expr, Expr.UnaryOp):
        op = expr.op
        arg = _ail_to_claripy(expr.operand, vv_map, mul_signed=mul_signed)
        if op == "Not":
            # Logical NOT (C's !) — returns 1 if arg==0, else 0
            n = arg.size()
            return claripy.If(arg == 0, claripy.BVV(1, n), claripy.BVV(0, n))
        raise NotImplementedError(f"Unsupported UnaryOp {op}")
    if isinstance(expr, Expr.BinaryOp):
        op = expr.op
        ops = expr.operands
        a = _ail_to_claripy(ops[0], vv_map, mul_signed=mul_signed)
        b = _ail_to_claripy(ops[1], vv_map, mul_signed=mul_signed)

        if op == "Add":
            return a + b
        if op == "Sub":
            return a - b
        if op == "Mul":
            return a * b
        if op == "And":
            return a & b
        if op == "Or":
            return a | b
        if op == "Xor":
            return a ^ b
        if op == "Shl":
            return a << b
        if op == "Shr":
            return claripy.LShR(a, b)

        if op == "CmpEQ":
            return claripy.If(a == b, claripy.BVV(1, 1), claripy.BVV(0, 1))
        if op == "CmpNE":
            return claripy.If(a != b, claripy.BVV(1, 1), claripy.BVV(0, 1))
        if op == "CmpLT":
            p = claripy.SLT(a, b) if expr.signed else claripy.ULT(a, b)
            return claripy.If(p, claripy.BVV(1, 1), claripy.BVV(0, 1))
        if op == "CmpLE":
            p = claripy.SLE(a, b) if expr.signed else claripy.ULE(a, b)
            return claripy.If(p, claripy.BVV(1, 1), claripy.BVV(0, 1))
        if op == "CmpGT":
            p = claripy.SGT(a, b) if expr.signed else claripy.UGT(a, b)
            return claripy.If(p, claripy.BVV(1, 1), claripy.BVV(0, 1))
        if op == "CmpGE":
            p = claripy.SGE(a, b) if expr.signed else claripy.UGE(a, b)
            return claripy.If(p, claripy.BVV(1, 1), claripy.BVV(0, 1))

        raise NotImplementedError(f"Unsupported BinaryOp {op}")
    raise NotImplementedError(f"Unsupported AIL expr type {type(expr)}")


def _assert_equiv(a: claripy.ast.BV, b: claripy.ast.BV):
    assert a.size() == b.size()
    s = claripy.Solver()
    s.add(a != b)
    assert not s.satisfiable()


def test_x86_cond_nz_sub_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondNZ"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_SUBL"]), 32),
            _const(0x40, 32),
            _const(0x41, 32),
            _const(0, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpNE"


def test_x86_cond_nle_sub_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondNLE"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_SUBL"]), 32),
            _const(0x80, 32),
            _const(0x7F, 32),
            _const(0, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpGT"


def test_x86_cond_nl_logic_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondNL"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_LOGICL"]), 32),
            _const(1, 32),
            _const(0, 32),
            _const(0, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpGE"


def test_x86_cond_z_incl_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondZ"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_INCL"]), 32),
            _const(0, 32),
            _const(0, 32),
            _const(0, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpEQ"


def test_x86_cond_b_sbbl_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondB"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_SBBL"]), 32),
            _const(1, 32),
            _const(2, 32),
            _const(1, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpLT"
    assert cmp_expr.signed is False


def test_x86_cond_l_sbbl_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondL"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_SBBL"]), 32),
            _const(1, 32),
            _const(2, 32),
            _const(1, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    # CondL + SBB now computes SF != OF explicitly (matching VEX semantics)
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpNE"


def test_amd64_cond_nz_add_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondNZ"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_ADDQ"]), 64),
            _const(1, 64),
            _const(2, 64),
            _const(0, 64),
        ),
        64,
    )
    result = AMD64CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpNE"
    assert isinstance(cmp_expr.operands[0], Expr.BinaryOp)
    assert cmp_expr.operands[0].op == "Add"


def test_amd64_cond_z_inc_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondZ"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_INCQ"]), 64),
            _const(0, 64),
            _const(0, 64),
            _const(0, 64),
        ),
        64,
    )
    result = AMD64CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpEQ"


def test_amd64_cond_z_shl_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondZ"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_SHLQ"]), 64),
            _const(0, 64),
            _const(0, 64),
            _const(0, 64),
        ),
        64,
    )
    result = AMD64CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpEQ"


def test_amd64_cond_o_umulq_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondO"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_UMULQ"]), 64),
            _const(2, 64),
            _const(3, 64),
            _const(0, 64),
        ),
        64,
    )
    result = AMD64CCallRewriter(ccall, None).result
    assert result is not None
    assert isinstance(result, Expr.Call)
    assert result.target == "__OFMUL__"


def test_amd64_cond_be_sub_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondBE"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_SUBQ"]), 64),
            _const(1, 64),
            _const(2, 64),
            _const(0, 64),
        ),
        64,
    )
    result = AMD64CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpLE"
    assert cmp_expr.signed is False


def test_amd64_cond_nb_sub_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondNB"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_SUBQ"]), 64),
            _const(2, 64),
            _const(1, 64),
            _const(0, 64),
        ),
        64,
    )
    result = AMD64CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpGE"
    assert cmp_expr.signed is False


def test_arm_cond_eq_sub_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondEQ, ARMG_CC_OP_SUB), 32),
            _const(0x40, 32),
            _const(0x41, 32),
            _const(0, 32),
        ),
        32,
    )
    result = ARMCCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpEQ"


def test_arm_cond_eq_logic_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondEQ, ARMG_CC_OP_LOGIC), 32),
            _const(0, 32),
            _const(0, 32),
            _const(0, 32),
        ),
        32,
    )
    result = ARMCCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpEQ"


def test_arm_cond_hs_logic_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondHS, ARMG_CC_OP_LOGIC), 32),
            _const(0, 32),
            _const(1, 32),
            _const(0, 32),
        ),
        32,
    )
    result = ARMCCallRewriter(ccall, None).result
    assert result is not None
    # CondHS + LOGIC returns dep2 directly (raw carry flag, matching VEX semantics)
    assert isinstance(result, Expr.Const)
    assert result.value == 1


def test_arm_cond_eq_add_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondEQ, ARMG_CC_OP_ADD), 32),
            _const(1, 32),
            _const(2, 32),
            _const(0, 32),
        ),
        32,
    )
    result = ARMCCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpEQ"
    assert isinstance(cmp_expr.operands[0], Expr.BinaryOp)
    assert cmp_expr.operands[0].op == "Add"


def test_arm_cond_hi_add_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondHI, ARMG_CC_OP_ADD), 32),
            _const(1, 32),
            _const(2, 32),
            _const(0, 32),
        ),
        32,
    )
    result = ARMCCallRewriter(ccall, None).result
    assert result is not None
    assert isinstance(result, Expr.Convert)
    assert isinstance(result.operands[0], Expr.BinaryOp)
    assert result.operands[0].op == "And"


def test_arm_cond_ls_add_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondLS, ARMG_CC_OP_ADD), 32),
            _const(1, 32),
            _const(2, 32),
            _const(0, 32),
        ),
        32,
    )
    result = ARMCCallRewriter(ccall, None).result
    assert result is not None
    assert isinstance(result, Expr.Convert)
    assert isinstance(result.operands[0], Expr.UnaryOp)
    assert result.operands[0].op == "Not"


def test_arm_cond_gt_add_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondGT, ARMG_CC_OP_ADD), 32),
            _const(1, 32),
            _const(2, 32),
            _const(0, 32),
        ),
        32,
    )
    result = ARMCCallRewriter(ccall, None).result
    assert result is not None
    assert isinstance(result, Expr.Convert)
    assert isinstance(result.operands[0], Expr.ITE)


def test_amd64_cond_nl_sub_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondNL"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_SUBQ"]), 64),
            _const(2, 64),
            _const(1, 64),
            _const(0, 64),
        ),
        64,
    )
    result = AMD64CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpGE"
    assert cmp_expr.signed is True


def test_x86_cond_s_add_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondS"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_ADDL"]), 32),
            _const(0x7FFFFFFF, 32),
            _const(1, 32),
            _const(0, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpLT"
    assert cmp_expr.signed is True
    assert isinstance(cmp_expr.operands[0], Expr.BinaryOp)
    assert cmp_expr.operands[0].op == "Add"


def test_x86_cond_ns_add_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondNS"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_ADDL"]), 32),
            _const(1, 32),
            _const(1, 32),
            _const(0, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpGE"
    assert cmp_expr.signed is True


def test_x86_cond_s_shr_rewrite():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondS"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_SHRL"]), 32),
            _const(0x80000000, 32),
            _const(0x40000000, 32),
            _const(0, 32),
        ),
        32,
    )
    result = X86CCallRewriter(ccall, None).result
    assert result is not None
    cmp_expr = _cmp_from_result(result)
    assert cmp_expr.op == "CmpLT"
    assert cmp_expr.signed is True


def test_x86_cond_o_addl_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondO"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_ADDL"]), 32),
            _vv(1, 32),
            _vv(2, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = X86CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 32), 2: claripy.BVS("b", 32), 3: claripy.BVS("ndep", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(X86_CondTypes["CondO"]), 32),
        claripy.BVV(_non_none_int(X86_OpTypes["G_CC_OP_ADDL"]), 32),
        vv_map[1],
        vv_map[2],
        vv_map[3],
        platform="X86",
    )
    _assert_equiv(rewritten, orig)


def test_x86_cond_o_incl_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondO"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_INCL"]), 32),
            _vv(1, 32),
            _const(0, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = X86CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("res", 32), 3: claripy.BVS("ndep", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(X86_CondTypes["CondO"]), 32),
        claripy.BVV(_non_none_int(X86_OpTypes["G_CC_OP_INCL"]), 32),
        vv_map[1],
        claripy.BVV(0, 32),
        vv_map[3],
        platform="X86",
    )
    _assert_equiv(rewritten, orig)


def test_x86_cond_b_addl_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondB"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_ADDL"]), 32),
            _vv(1, 32),
            _vv(2, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = X86CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 32), 2: claripy.BVS("b", 32), 3: claripy.BVS("ndep", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(X86_CondTypes["CondB"]), 32),
        claripy.BVV(_non_none_int(X86_OpTypes["G_CC_OP_ADDL"]), 32),
        vv_map[1],
        vv_map[2],
        vv_map[3],
        platform="X86",
    )
    _assert_equiv(rewritten, orig)


def test_x86_cond_be_addl_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondBE"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_ADDL"]), 32),
            _vv(1, 32),
            _vv(2, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = X86CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 32), 2: claripy.BVS("b", 32), 3: claripy.BVS("ndep", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(X86_CondTypes["CondBE"]), 32),
        claripy.BVV(_non_none_int(X86_OpTypes["G_CC_OP_ADDL"]), 32),
        vv_map[1],
        vv_map[2],
        vv_map[3],
        platform="X86",
    )
    _assert_equiv(rewritten, orig)


def test_x86_cond_le_decl_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondLE"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_DECL"]), 32),
            _vv(1, 32),
            _const(0, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = X86CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("res", 32), 3: claripy.BVS("ndep", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(X86_CondTypes["CondLE"]), 32),
        claripy.BVV(_non_none_int(X86_OpTypes["G_CC_OP_DECL"]), 32),
        vv_map[1],
        claripy.BVV(0, 32),
        vv_map[3],
        platform="X86",
    )
    _assert_equiv(rewritten, orig)


def test_x86_cond_nle_decl_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes["CondNLE"]), 32),
            _const(_non_none_int(X86_OpTypes["G_CC_OP_DECL"]), 32),
            _vv(1, 32),
            _const(0, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = X86CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("res", 32), 3: claripy.BVS("ndep", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(X86_CondTypes["CondNLE"]), 32),
        claripy.BVV(_non_none_int(X86_OpTypes["G_CC_OP_DECL"]), 32),
        vv_map[1],
        claripy.BVV(0, 32),
        vv_map[3],
        platform="X86",
    )
    _assert_equiv(rewritten, orig)


def test_amd64_cond_le_decq_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondLE"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_DECQ"]), 64),
            _vv(1, 64),
            _const(0, 64),
            _vv(3, 64),
        ),
        64,
    )
    ail = AMD64CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("res", 64), 3: claripy.BVS("ndep", 64)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(AMD64_CondTypes["CondLE"]), 64),
        claripy.BVV(_non_none_int(AMD64_OpTypes["G_CC_OP_DECQ"]), 64),
        vv_map[1],
        claripy.BVV(0, 64),
        vv_map[3],
        platform="AMD64",
    )
    _assert_equiv(rewritten, orig)


def test_amd64_cond_nle_decq_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes["CondNLE"]), 64),
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_DECQ"]), 64),
            _vv(1, 64),
            _const(0, 64),
            _vv(3, 64),
        ),
        64,
    )
    ail = AMD64CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("res", 64), 3: claripy.BVS("ndep", 64)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(AMD64_CondTypes["CondNLE"]), 64),
        claripy.BVV(_non_none_int(AMD64_OpTypes["G_CC_OP_DECQ"]), 64),
        vv_map[1],
        claripy.BVV(0, 64),
        vv_map[3],
        platform="AMD64",
    )
    _assert_equiv(rewritten, orig)


def test_amd64_rflags_c_addq_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_rflags_c",
        (
            _const(_non_none_int(AMD64_OpTypes["G_CC_OP_ADDQ"]), 64),
            _vv(1, 64),
            _vv(2, 64),
            _vv(3, 64),
        ),
        64,
    )
    ail = AMD64CCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 64), 2: claripy.BVS("b", 64), 3: claripy.BVS("ndep", 64)}
    rewritten = _ail_to_claripy(ail, vv_map)
    res = vv_map[1] + vv_map[2]
    expected = claripy.If(claripy.ULT(res, vv_map[1]), claripy.BVV(1, 64), claripy.BVV(0, 64))
    _assert_equiv(rewritten, expected)


def test_arm_cond_mi_sub_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondMI, ARMG_CC_OP_SUB), 32),
            _vv(1, 32),
            _vv(2, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = ARMCCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 32), 2: claripy.BVS("b", 32), 3: claripy.BVS("c", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.armg_calculate_condition(
        None, claripy.BVV(_arm_cond_n_op(ARMCondMI, ARMG_CC_OP_SUB), 32), vv_map[1], vv_map[2], vv_map[3]
    )
    _assert_equiv(rewritten, orig)


def test_arm_cond_pl_sub_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondPL, ARMG_CC_OP_SUB), 32),
            _vv(1, 32),
            _vv(2, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = ARMCCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 32), 2: claripy.BVS("b", 32), 3: claripy.BVS("c", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.armg_calculate_condition(
        None, claripy.BVV(_arm_cond_n_op(ARMCondPL, ARMG_CC_OP_SUB), 32), vv_map[1], vv_map[2], vv_map[3]
    )
    _assert_equiv(rewritten, orig)


def test_arm_cond_hs_sbb_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondHS, ARMG_CC_OP_SBB), 32),
            _vv(1, 32),
            _vv(2, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = ARMCCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 32), 2: claripy.BVS("b", 32), 3: claripy.BVS("oldc", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.armg_calculate_condition(
        None, claripy.BVV(_arm_cond_n_op(ARMCondHS, ARMG_CC_OP_SBB), 32), vv_map[1], vv_map[2], vv_map[3]
    )
    _assert_equiv(rewritten, orig)


def test_arm_cond_lo_sbb_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondLO, ARMG_CC_OP_SBB), 32),
            _vv(1, 32),
            _vv(2, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = ARMCCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 32), 2: claripy.BVS("b", 32), 3: claripy.BVS("oldc", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.armg_calculate_condition(
        None, claripy.BVV(_arm_cond_n_op(ARMCondLO, ARMG_CC_OP_SBB), 32), vv_map[1], vv_map[2], vv_map[3]
    )
    _assert_equiv(rewritten, orig)


def test_arm_cond_le_sub_equiv():
    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (
            _const(_arm_cond_n_op(ARMCondLE, ARMG_CC_OP_SUB), 32),
            _vv(1, 32),
            _vv(2, 32),
            _vv(3, 32),
        ),
        32,
    )
    ail = ARMCCallRewriter(ccall, None).result
    assert ail is not None
    vv_map = {1: claripy.BVS("a", 32), 2: claripy.BVS("b", 32), 3: claripy.BVS("c", 32)}
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.armg_calculate_condition(
        None, claripy.BVV(_arm_cond_n_op(ARMCondLE, ARMG_CC_OP_SUB), 32), vv_map[1], vv_map[2], vv_map[3]
    )
    _assert_equiv(rewritten, orig)


# =====================================================================
# Helpers for parametrized semantic tests
# =====================================================================


def _op_category(op_name: str) -> str:
    for cat in ("SBB", "ADC", "UMUL", "SMUL", "SUB", "ADD", "LOGIC", "INC", "DEC", "SHL", "SHR", "COPY"):
        if cat in op_name:
            return cat
    return op_name


def _make_operands(op_name: str, bits: int):
    """Create AIL operands and claripy symbols matching VEX convention for *op_name*."""
    cat = _op_category(op_name)
    dep1_a, dep1_c = _vv(1, bits), claripy.BVS("dep1", bits)
    vv_map: dict[int, claripy.ast.BV] = {1: dep1_c}

    if cat in ("SUB", "ADD", "UMUL", "SMUL"):
        dep2_a, dep2_c = _vv(2, bits), claripy.BVS("dep2", bits)
        ndep_a, ndep_c = _const(0, bits), claripy.BVV(0, bits)
        vv_map[2] = dep2_c
    elif cat in ("LOGIC", "COPY"):
        dep2_a, dep2_c = _const(0, bits), claripy.BVV(0, bits)
        ndep_a, ndep_c = _const(0, bits), claripy.BVV(0, bits)
    elif cat in ("INC", "DEC"):
        dep2_a, dep2_c = _const(0, bits), claripy.BVV(0, bits)
        ndep_a, ndep_c = _vv(3, bits), claripy.BVS("ndep", bits)
        vv_map[3] = ndep_c
    elif cat in ("SHL", "SHR"):
        dep2_a, dep2_c = _vv(2, bits), claripy.BVS("dep2", bits)
        ndep_a, ndep_c = _const(0, bits), claripy.BVV(0, bits)
        vv_map[2] = dep2_c
    elif cat in ("SBB", "ADC"):
        dep2_a, dep2_c = _vv(2, bits), claripy.BVS("dep2", bits)
        ndep_a, ndep_c = _vv(3, bits), claripy.BVS("ndep", bits)
        vv_map[2] = dep2_c
        vv_map[3] = ndep_c
    else:
        dep2_a, dep2_c = _vv(2, bits), claripy.BVS("dep2", bits)
        ndep_a, ndep_c = _const(0, bits), claripy.BVV(0, bits)
        vv_map[2] = dep2_c

    return dep1_a, dep2_a, ndep_a, dep1_c, dep2_c, ndep_c, vv_map


# =====================================================================
# Parametrized X86 semantic tests
# =====================================================================

X86_COND_OP_CASES = [
    # CondLE / CondNLE
    ("CondLE", "G_CC_OP_SUBL"),
    ("CondNLE", "G_CC_OP_SUBL"),
    ("CondLE", "G_CC_OP_ADDL"),
    ("CondNLE", "G_CC_OP_ADDL"),
    ("CondLE", "G_CC_OP_LOGICL"),
    ("CondNLE", "G_CC_OP_LOGICL"),
    ("CondLE", "G_CC_OP_DECL"),
    ("CondNLE", "G_CC_OP_DECL"),
    # CondO / CondNO
    ("CondO", "G_CC_OP_UMULL"),
    ("CondO", "G_CC_OP_SMULL"),
    ("CondO", "G_CC_OP_ADDL"),
    ("CondO", "G_CC_OP_INCL"),
    ("CondO", "G_CC_OP_ADCL"),
    ("CondO", "G_CC_OP_SBBL"),
    ("CondNO", "G_CC_OP_UMULL"),
    ("CondNO", "G_CC_OP_SMULL"),
    ("CondNO", "G_CC_OP_ADDL"),
    ("CondNO", "G_CC_OP_INCL"),
    ("CondNO", "G_CC_OP_ADCL"),
    ("CondNO", "G_CC_OP_SBBL"),
    # CondZ / CondNZ
    ("CondZ", "G_CC_OP_ADDL"),
    ("CondNZ", "G_CC_OP_ADDL"),
    ("CondZ", "G_CC_OP_SUBL"),
    ("CondNZ", "G_CC_OP_SUBL"),
    ("CondZ", "G_CC_OP_LOGICL"),
    ("CondNZ", "G_CC_OP_LOGICL"),
    ("CondZ", "G_CC_OP_COPY"),
    ("CondNZ", "G_CC_OP_COPY"),
    ("CondZ", "G_CC_OP_INCL"),
    ("CondNZ", "G_CC_OP_INCL"),
    ("CondZ", "G_CC_OP_DECL"),
    ("CondNZ", "G_CC_OP_DECL"),
    ("CondZ", "G_CC_OP_SHLL"),
    ("CondNZ", "G_CC_OP_SHLL"),
    ("CondZ", "G_CC_OP_SHRL"),
    ("CondNZ", "G_CC_OP_SHRL"),
    # CondL / CondNL
    ("CondL", "G_CC_OP_SUBL"),
    ("CondNL", "G_CC_OP_SUBL"),
    ("CondL", "G_CC_OP_LOGICL"),
    ("CondNL", "G_CC_OP_LOGICL"),
    ("CondL", "G_CC_OP_SBBL"),
    ("CondNL", "G_CC_OP_SBBL"),
    # CondBE / CondB
    ("CondBE", "G_CC_OP_ADDL"),
    ("CondB", "G_CC_OP_ADDL"),
    ("CondBE", "G_CC_OP_SUBL"),
    ("CondB", "G_CC_OP_SUBL"),
    ("CondBE", "G_CC_OP_LOGICL"),
    ("CondB", "G_CC_OP_LOGICL"),
    ("CondBE", "G_CC_OP_SBBL"),
    ("CondB", "G_CC_OP_SBBL"),
    ("CondB", "G_CC_OP_ADCL"),
    # CondNB / CondNBE
    ("CondNB", "G_CC_OP_SBBL"),
    ("CondNBE", "G_CC_OP_SBBL"),
    ("CondNB", "G_CC_OP_SUBL"),
    ("CondNBE", "G_CC_OP_SUBL"),
    # CondS / CondNS
    ("CondS", "G_CC_OP_ADDL"),
    ("CondNS", "G_CC_OP_ADDL"),
    ("CondS", "G_CC_OP_LOGICL"),
    ("CondNS", "G_CC_OP_LOGICL"),
    ("CondS", "G_CC_OP_SHRL"),
    ("CondNS", "G_CC_OP_SHRL"),
    ("CondS", "G_CC_OP_SUBL"),
    ("CondNS", "G_CC_OP_SUBL"),
    ("CondS", "G_CC_OP_SHLL"),
    ("CondNS", "G_CC_OP_SHLL"),
    # Byte/Word-width variants that call _fix_size
    ("CondLE", "G_CC_OP_SUBB"),
    ("CondLE", "G_CC_OP_SUBW"),
    ("CondS", "G_CC_OP_ADDB"),
]


@pytest.mark.parametrize("cond_name,op_name", X86_COND_OP_CASES)
def test_x86_semantic(cond_name, op_name):
    bits = 32
    dep1_a, dep2_a, ndep_a, dep1_c, dep2_c, ndep_c, vv_map = _make_operands(op_name, bits)
    ccall = Expr.VEXCCallExpression(
        None,
        "x86g_calculate_condition",
        (
            _const(_non_none_int(X86_CondTypes[cond_name]), bits),
            _const(_non_none_int(X86_OpTypes[op_name]), bits),
            dep1_a,
            dep2_a,
            ndep_a,
        ),
        bits,
    )
    ail = X86CCallRewriter(ccall, None).result
    assert ail is not None, f"Rewriter returned None for {cond_name}+{op_name}"
    mul_signed = _op_category(op_name) == "SMUL"
    rewritten = _ail_to_claripy(ail, vv_map, mul_signed=mul_signed)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(X86_CondTypes[cond_name]), bits),
        claripy.BVV(_non_none_int(X86_OpTypes[op_name]), bits),
        dep1_c,
        dep2_c,
        ndep_c,
        platform="X86",
    )
    _assert_equiv(rewritten, orig)


# =====================================================================
# Parametrized AMD64 semantic tests
# =====================================================================

AMD64_COND_OP_CASES = [
    # CondLE / CondNLE
    ("CondLE", "G_CC_OP_SUBQ"),
    ("CondNLE", "G_CC_OP_SUBQ"),
    ("CondLE", "G_CC_OP_LOGICQ"),
    ("CondNLE", "G_CC_OP_LOGICQ"),
    ("CondLE", "G_CC_OP_DECQ"),
    ("CondNLE", "G_CC_OP_DECQ"),
    # CondZ / CondNZ
    ("CondZ", "G_CC_OP_ADDQ"),
    ("CondNZ", "G_CC_OP_ADDQ"),
    ("CondZ", "G_CC_OP_SUBQ"),
    ("CondNZ", "G_CC_OP_SUBQ"),
    ("CondZ", "G_CC_OP_LOGICQ"),
    ("CondNZ", "G_CC_OP_LOGICQ"),
    ("CondZ", "G_CC_OP_SHLQ"),
    ("CondNZ", "G_CC_OP_SHLQ"),
    ("CondZ", "G_CC_OP_SHRQ"),
    ("CondNZ", "G_CC_OP_SHRQ"),
    ("CondZ", "G_CC_OP_COPY"),
    ("CondNZ", "G_CC_OP_COPY"),
    ("CondZ", "G_CC_OP_INCQ"),
    ("CondNZ", "G_CC_OP_INCQ"),
    ("CondZ", "G_CC_OP_DECQ"),
    ("CondNZ", "G_CC_OP_DECQ"),
    # CondO / CondNO
    ("CondO", "G_CC_OP_UMULQ"),
    ("CondO", "G_CC_OP_SMULQ"),
    ("CondO", "G_CC_OP_SMULL"),
    ("CondO", "G_CC_OP_ADDQ"),
    ("CondO", "G_CC_OP_ADDB"),
    ("CondNO", "G_CC_OP_UMULQ"),
    ("CondNO", "G_CC_OP_SMULQ"),
    ("CondNO", "G_CC_OP_SMULL"),
    ("CondNO", "G_CC_OP_ADDQ"),
    ("CondNO", "G_CC_OP_ADDB"),
    # CondL / CondNL
    ("CondL", "G_CC_OP_SUBQ"),
    ("CondNL", "G_CC_OP_SUBQ"),
    ("CondL", "G_CC_OP_LOGICQ"),
    ("CondNL", "G_CC_OP_LOGICQ"),
    # CondNBE / CondBE / CondNB / CondB
    ("CondNBE", "G_CC_OP_SUBQ"),
    ("CondBE", "G_CC_OP_SUBQ"),
    ("CondNB", "G_CC_OP_SUBQ"),
    ("CondB", "G_CC_OP_SUBQ"),
    ("CondB", "G_CC_OP_SBBQ"),
    # CondS / CondNS
    ("CondS", "G_CC_OP_ADDQ"),
    ("CondNS", "G_CC_OP_ADDQ"),
    ("CondS", "G_CC_OP_SUBQ"),
    ("CondNS", "G_CC_OP_SUBQ"),
    ("CondS", "G_CC_OP_LOGICQ"),
    ("CondNS", "G_CC_OP_LOGICQ"),
    ("CondS", "G_CC_OP_SHLQ"),
    ("CondNS", "G_CC_OP_SHLQ"),
    ("CondS", "G_CC_OP_SHRQ"),
    ("CondNS", "G_CC_OP_SHRQ"),
    ("CondS", "G_CC_OP_INCQ"),
    ("CondNS", "G_CC_OP_INCQ"),
    ("CondS", "G_CC_OP_DECQ"),
    ("CondNS", "G_CC_OP_DECQ"),
    # Width variants that call _fix_size
    ("CondLE", "G_CC_OP_SUBB"),
    ("CondLE", "G_CC_OP_SUBL"),
]
# Note: CondB+ADD skipped (creates Expr.Call requiring project)


@pytest.mark.parametrize("cond_name,op_name", AMD64_COND_OP_CASES)
def test_amd64_semantic(cond_name, op_name):
    bits = 64
    dep1_a, dep2_a, ndep_a, dep1_c, dep2_c, ndep_c, vv_map = _make_operands(op_name, bits)
    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_condition",
        (
            _const(_non_none_int(AMD64_CondTypes[cond_name]), bits),
            _const(_non_none_int(AMD64_OpTypes[op_name]), bits),
            dep1_a,
            dep2_a,
            ndep_a,
        ),
        bits,
    )
    ail = AMD64CCallRewriter(ccall, None).result
    assert ail is not None, f"Rewriter returned None for {cond_name}+{op_name}"
    mul_signed = _op_category(op_name) == "SMUL"
    rewritten = _ail_to_claripy(ail, vv_map, mul_signed=mul_signed)
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(AMD64_CondTypes[cond_name]), bits),
        claripy.BVV(_non_none_int(AMD64_OpTypes[op_name]), bits),
        dep1_c,
        dep2_c,
        ndep_c,
        platform="AMD64",
    )
    _assert_equiv(rewritten, orig)


# =====================================================================
# Parametrized AMD64 rflags_c semantic tests
# =====================================================================

AMD64_RFLAGS_C_CASES = [
    "G_CC_OP_ADDQ",
    "G_CC_OP_SUBQ",
    "G_CC_OP_DECQ",
    # Width variants
    "G_CC_OP_ADDB",
    "G_CC_OP_SUBB",
    "G_CC_OP_DECB",
]


@pytest.mark.parametrize("op_name", AMD64_RFLAGS_C_CASES)
def test_amd64_rflags_c_semantic(op_name):
    bits = 64
    cat = _op_category(op_name)
    dep1_a, dep1_c = _vv(1, bits), claripy.BVS("dep1", bits)
    vv_map: dict[int, claripy.ast.BV] = {1: dep1_c}

    if cat in ("ADD", "SUB"):
        dep2_a, dep2_c = _vv(2, bits), claripy.BVS("dep2", bits)
        ndep_a, ndep_c = _const(0, bits), claripy.BVV(0, bits)
        vv_map[2] = dep2_c
    else:
        # DEC: dep2=0, ndep=symbolic (old flags)
        dep2_a, dep2_c = _const(0, bits), claripy.BVV(0, bits)
        ndep_a, ndep_c = _vv(3, bits), claripy.BVS("ndep", bits)
        vv_map[3] = ndep_c

    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_rflags_c",
        (
            _const(_non_none_int(AMD64_OpTypes[op_name]), bits),
            dep1_a,
            dep2_a,
            ndep_a,
        ),
        bits,
    )
    ail = AMD64CCallRewriter(ccall, None).result
    assert ail is not None, f"Rewriter returned None for rflags_c+{op_name}"
    rewritten = _ail_to_claripy(ail, vv_map)

    # Compute expected carry flag via VEX semantics:
    # CondB = carry flag for x86/amd64
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(_non_none_int(AMD64_CondTypes["CondB"]), bits),
        claripy.BVV(_non_none_int(AMD64_OpTypes[op_name]), bits),
        dep1_c,
        dep2_c,
        ndep_c,
        platform="AMD64",
    )
    _assert_equiv(rewritten, orig)


# =====================================================================
# Parametrized ARM semantic tests
# =====================================================================

ARM_COND_OP_CASES = [
    # CondEQ
    (ARMCondEQ, ARMG_CC_OP_SUB, "EQ_SUB"),
    (ARMCondEQ, ARMG_CC_OP_LOGIC, "EQ_LOGIC"),
    (ARMCondEQ, ARMG_CC_OP_ADD, "EQ_ADD"),
    # CondNE
    (ARMCondNE, ARMG_CC_OP_SUB, "NE_SUB"),
    # CondHS / CondLO
    (ARMCondHS, ARMG_CC_OP_SBB, "HS_SBB"),
    (ARMCondLO, ARMG_CC_OP_SBB, "LO_SBB"),
    (ARMCondHS, ARMG_CC_OP_LOGIC, "HS_LOGIC"),
    (ARMCondLO, ARMG_CC_OP_LOGIC, "LO_LOGIC"),
    (ARMCondHS, ARMG_CC_OP_ADD, "HS_ADD"),
    (ARMCondLO, ARMG_CC_OP_ADD, "LO_ADD"),
    # CondMI / CondPL
    (ARMCondMI, ARMG_CC_OP_SUB, "MI_SUB"),
    (ARMCondPL, ARMG_CC_OP_SUB, "PL_SUB"),
    (ARMCondMI, ARMG_CC_OP_ADD, "MI_ADD"),
    (ARMCondPL, ARMG_CC_OP_ADD, "PL_ADD"),
    # CondLE
    (ARMCondLE, ARMG_CC_OP_SUB, "LE_SUB"),
    (ARMCondLE, ARMG_CC_OP_ADD, "LE_ADD"),
    # CondHI / CondLS
    (ARMCondHI, ARMG_CC_OP_ADD, "HI_ADD"),
    (ARMCondLS, ARMG_CC_OP_ADD, "LS_ADD"),
    # CondGE / CondLT
    (ARMCondGE, ARMG_CC_OP_ADD, "GE_ADD"),
    (ARMCondLT, ARMG_CC_OP_ADD, "LT_ADD"),
    # CondGT
    (ARMCondGT, ARMG_CC_OP_ADD, "GT_ADD"),
]


@pytest.mark.parametrize("cond_v,op_v,label", ARM_COND_OP_CASES, ids=lambda x: x if isinstance(x, str) else "")
def test_arm_semantic(cond_v, op_v, label):
    bits = 32
    cond_n_op = _arm_cond_n_op(cond_v, op_v)

    dep1_a, dep1_c = _vv(1, bits), claripy.BVS("dep1", bits)
    dep2_a, dep2_c = _vv(2, bits), claripy.BVS("dep2", bits)
    vv_map: dict[int, claripy.ast.BV] = {1: dep1_c, 2: dep2_c}

    if op_v == ARMG_CC_OP_SBB:
        dep3_a, dep3_c = _vv(3, bits), claripy.BVS("dep3", bits)
        vv_map[3] = dep3_c
    else:
        dep3_a, dep3_c = _const(0, bits), claripy.BVV(0, bits)

    ccall = Expr.VEXCCallExpression(
        None,
        "armg_calculate_condition",
        (_const(cond_n_op, bits), dep1_a, dep2_a, dep3_a),
        bits,
    )
    ail = ARMCCallRewriter(ccall, None).result
    assert ail is not None, f"Rewriter returned None for ARM {label}"
    rewritten = _ail_to_claripy(ail, vv_map)
    orig = ccall_sem.armg_calculate_condition(None, claripy.BVV(cond_n_op, bits), dep1_c, dep2_c, dep3_c)
    _assert_equiv(rewritten, orig)
