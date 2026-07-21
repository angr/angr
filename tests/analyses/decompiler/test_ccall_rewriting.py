#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import itertools
import os
import unittest

import claripy

import angr
from angr.ailment import Expr, Manager
from angr.analyses.decompiler.ccall_rewriters.amd64_ccalls import AMD64CCallRewriter
from angr.engines.vex.claripy.ccall import data, pc_calculate_condition
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

AMD64_CondTypes = data["AMD64"]["CondTypes"]
AMD64_OpTypes = data["AMD64"]["OpTypes"]
AMD64_CondBitMasks = data["AMD64"]["CondBitMasks"]


class TestCCallRewriting(unittest.TestCase):
    def test_NtGetCurrentPeb(self):
        bin_path = os.path.join(
            test_location, "i386", "windows", "48460c9633d06cad3e3b41c87de04177d129906610c5bbdebc7507a211100e98"
        )
        proj = angr.Project(bin_path)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)
        func = cfg.functions[0x401030]
        assert func is not None

        dec = proj.analyses.Decompiler(func, cfg=cfg, options=[("semvar_naming", False)])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert "PEB * sub_401030(void)" in dec.codegen.text
        assert "PEB *v0;" in dec.codegen.text
        assert "v0 = NtGetCurrentPeb();" in dec.codegen.text


def _make_ccall(cond, op, dep1=None, dep2=None, ndep=None, bits=64):
    """Build a VEXCCallExpression for amd64g_calculate_condition."""
    if dep1 is None:
        dep1 = Expr.Register(1, 16, 64)  # rax
    if dep2 is None:
        dep2 = Expr.Register(2, 24, 64)  # rcx
    if ndep is None:
        ndep = Expr.Const(3, 0, 64)
    return Expr.VEXCCallExpression(
        idx=0,
        callee="amd64g_calculate_condition",
        operands=(Expr.Const(0, cond, 64), Expr.Const(0, op, 64), dep1, dep2, ndep),
        bits=bits,
    )


_PROJECT = angr.load_shellcode(b"\x90", arch="AMD64")


def _rewrite(ccall):
    return AMD64CCallRewriter(ccall, _PROJECT, Manager(arch=_PROJECT.arch)).result


def _unwrap_convert(expr):
    """Strip an outer Convert wrapper if present."""
    return expr.operand if isinstance(expr, Expr.Convert) else expr


def _mask(v, bits):
    return v & ((1 << bits) - 1)


def _sext(v, bits):
    v = _mask(v, bits)
    return v - (1 << bits) if v >> (bits - 1) else v


def _eval(expr):
    """Concretely evaluate a rewritten (constant-folded) AIL expression. Returns (value, bits)."""
    if isinstance(expr, Expr.Const):
        return _mask(expr.value_int, expr.bits), expr.bits
    if isinstance(expr, Expr.Convert):
        v, _ = _eval(expr.operand)
        v = _mask(_sext(v, expr.from_bits) if expr.is_signed else v, expr.to_bits)
        return v, expr.to_bits
    if isinstance(expr, Expr.Call) and expr.target == "__CFADD__":
        # carry-out of the addition at the operands' width
        left, lbits = _eval(expr.args[0])
        right, rbits = _eval(expr.args[1])
        bits = max(lbits, rbits)
        return int(_mask(left + right, bits) < left), expr.bits
    if isinstance(expr, Expr.BinaryOp):
        left, lbits = _eval(expr.operands[0])
        right, rbits = _eval(expr.operands[1])
        bits = max(lbits, rbits)
        if expr.signed:
            left, right = _sext(left, lbits), _sext(right, rbits)
        cmps = {
            "CmpEQ": lambda: (int(left == right), 1),
            "CmpNE": lambda: (int(left != right), 1),
            "CmpLT": lambda: (int(left < right), 1),
            "CmpLE": lambda: (int(left <= right), 1),
            "CmpGT": lambda: (int(left > right), 1),
            "CmpGE": lambda: (int(left >= right), 1),
            "And": lambda: (_mask(left & right, bits), bits),
            "Add": lambda: (_mask(left + right, bits), bits),
        }
        if expr.op not in cmps:
            raise NotImplementedError(expr.op)
        return cmps[expr.op]()
    raise NotImplementedError(type(expr))


def _oracle(cond, op, dep1, dep2, ndep=0):
    """Ground truth: ccall.py's executable amd64g_calculate_condition."""
    r = pc_calculate_condition(
        None,
        claripy.BVV(cond, 64),
        claripy.BVV(op, 64),
        claripy.BVV(dep1, 64),
        claripy.BVV(dep2, 64),
        claripy.BVV(ndep, 64),
        platform="AMD64",
    )
    return bool(claripy.backends.concrete.eval(r, 1)[0])


def _rewritten_value(cond, op, dep1, dep2, ndep=0):
    ccall = _make_ccall(cond, op, Expr.Const(1, dep1, 64), Expr.Const(2, dep2, 64), Expr.Const(3, ndep, 64))
    result = _rewrite(ccall)
    assert result is not None
    return bool(_eval(result)[0])


class TestAMD64CCallRewriterCondNL(unittest.TestCase):
    """CondNL (jge, SF == OF). Signed >= over SUB; sign-of-result >= 0 over LOGIC."""

    def test_condnl_sub_is_signed_ge(self):
        for op in ("G_CC_OP_SUBB", "G_CC_OP_SUBW", "G_CC_OP_SUBL", "G_CC_OP_SUBQ"):
            cmp = _unwrap_convert(_rewrite(_make_ccall(AMD64_CondTypes["CondNL"], AMD64_OpTypes[op])))
            assert isinstance(cmp, Expr.BinaryOp), f"{op}: not rewritten"
            assert cmp.op == "CmpGE", f"{op}: got {cmp.op}"
            assert cmp.signed is True, f"{op}: expected signed"

    def test_condnl_logic_is_signed_ge_zero(self):
        for op in ("G_CC_OP_LOGICB", "G_CC_OP_LOGICW", "G_CC_OP_LOGICL", "G_CC_OP_LOGICQ"):
            cmp = _unwrap_convert(_rewrite(_make_ccall(AMD64_CondTypes["CondNL"], AMD64_OpTypes[op])))
            assert isinstance(cmp, Expr.BinaryOp), f"{op}: not rewritten"
            assert cmp.op == "CmpGE", f"{op}: got {cmp.op}"
            assert cmp.signed is True, f"{op}: expected signed"
            assert cmp.operands[1].value_int == 0, f"{op}: expected comparison against 0"


_DEP2_SAMPLE = (0, 1, 2, 3, 0x7E, 0x7F, 0x80, 0x81, 0xFD, 0xFE, 0xFF, 0x55)


class TestAMD64CCallRewriterDifferential(unittest.TestCase):
    """Differential-test 8-bit cells against ccall.py's executable semantics."""

    # VEX only guarantees the low nbits of the deps; the rewriter must ignore anything above them
    _DIRTY = 0xDEADBEEF_00000100

    def _sweep(self, cond_name, op_name):
        cond, op = AMD64_CondTypes[cond_name], AMD64_OpTypes[op_name]
        for dep1, dep2 in itertools.product(range(256), _DEP2_SAMPLE):
            got = _rewritten_value(cond, op, dep1, dep2)
            want = _oracle(cond, op, dep1, dep2)
            assert got == want, f"{cond_name} x {op_name} dep1={dep1:#x} dep2={dep2:#x}: {got} != {want}"
            if dep1 % 8 == 0:
                d1, d2 = dep1 | self._DIRTY, dep2 | self._DIRTY
                got = _rewritten_value(cond, op, d1, d2)
                want = _oracle(cond, op, d1, d2)
                assert got == want, f"{cond_name} x {op_name} dep1={d1:#x} dep2={d2:#x}: {got} != {want}"

    def test_condnl_subb_differential(self):
        self._sweep("CondNL", "G_CC_OP_SUBB")

    def test_condnl_logicb_differential(self):
        self._sweep("CondNL", "G_CC_OP_LOGICB")


if __name__ == "__main__":
    unittest.main()
