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


#
# AMD64 rewriter unit tests: build amd64g_calculate_condition ccalls in memory, rewrite them,
# and differential-test the rewritten expressions against ccall.py's executable semantics.
#


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


class TestAMD64CCallRewriterCondBE(unittest.TestCase):
    """CondBE (jbe / unsigned <=) recovery. Previously unhandled, leaving a generic `_ccall`."""

    def test_condbe_sub_is_unsigned_le(self):
        for op in ("G_CC_OP_SUBB", "G_CC_OP_SUBW", "G_CC_OP_SUBL", "G_CC_OP_SUBQ"):
            ccall = _make_ccall(AMD64_CondTypes["CondBE"], AMD64_OpTypes[op])
            result = _unwrap_convert(_rewrite(ccall))
            assert isinstance(result, Expr.BinaryOp), f"{op}: not rewritten"
            assert result.op == "CmpLE", f"{op}: got {result.op}"
            assert result.signed is False, f"{op}: expected unsigned"

    def test_condb_sub_still_unsigned_lt(self):
        # control: CondB must be unchanged by the CondBE addition
        for op in ("G_CC_OP_SUBB", "G_CC_OP_SUBW", "G_CC_OP_SUBL", "G_CC_OP_SUBQ"):
            ccall = _make_ccall(AMD64_CondTypes["CondB"], AMD64_OpTypes[op])
            result = _unwrap_convert(_rewrite(ccall))
            assert isinstance(result, Expr.BinaryOp), f"{op}: not rewritten"
            assert result.op == "CmpLT", f"{op}: got {result.op}"
            assert result.signed is False, f"{op}: expected unsigned"

    def test_condb_add_still_uses_cfadd(self):
        # control: CondB x ADD must keep emitting __CFADD__, not a comparison
        ccall = _make_ccall(AMD64_CondTypes["CondB"], AMD64_OpTypes["G_CC_OP_ADDL"])
        result = _rewrite(ccall)
        assert isinstance(result, Expr.Call) and result.target == "__CFADD__"

    def test_condbe_add_is_not_rewritten(self):
        # CondBE x ADD needs CF|ZF, which the CondB __CFADD__ form does not express: leave it alone
        ccall = _make_ccall(AMD64_CondTypes["CondBE"], AMD64_OpTypes["G_CC_OP_ADDL"])
        assert _rewrite(ccall) is None

    def test_condbe_logic_is_zero_test(self):
        # and/or/xor clear CF, so BE == CF|ZF degenerates to ZF
        ccall = _make_ccall(AMD64_CondTypes["CondBE"], AMD64_OpTypes["G_CC_OP_LOGICL"])
        result = _unwrap_convert(_rewrite(ccall))
        assert isinstance(result, Expr.BinaryOp) and result.op == "CmpEQ"

    def test_condb_logic_is_always_false(self):
        ccall = _make_ccall(AMD64_CondTypes["CondB"], AMD64_OpTypes["G_CC_OP_LOGICL"])
        result = _rewrite(ccall)
        assert isinstance(result, Expr.Const) and result.value_int == 0
        assert result.bits == ccall.bits

    def test_condnb_sub_is_unsigned_ge(self):
        for op in ("G_CC_OP_SUBB", "G_CC_OP_SUBW", "G_CC_OP_SUBL", "G_CC_OP_SUBQ"):
            ccall = _make_ccall(AMD64_CondTypes["CondNB"], AMD64_OpTypes[op])
            result = _unwrap_convert(_rewrite(ccall))
            assert isinstance(result, Expr.BinaryOp), f"{op}: not rewritten"
            assert result.op == "CmpGE", f"{op}: got {result.op}"
            assert result.signed is False, f"{op}: expected unsigned"

    def test_condnb_add_is_negated_cfadd(self):
        # CondNB (jae) is !CF, the negation of the __CFADD__ carry test CondB emits.
        # An inline (a + b) >= a comparison would be a C-promotion tautology at 8/16-bit widths.
        for op in ("G_CC_OP_ADDB", "G_CC_OP_ADDW", "G_CC_OP_ADDL", "G_CC_OP_ADDQ"):
            ccall = _make_ccall(AMD64_CondTypes["CondNB"], AMD64_OpTypes[op])
            result = _unwrap_convert(_rewrite(ccall))
            assert isinstance(result, Expr.BinaryOp), f"{op}: not rewritten"
            assert result.op == "CmpEQ", f"{op}: got {result.op}"
            lhs, rhs = result.operands
            assert isinstance(lhs, Expr.Call) and lhs.target == "__CFADD__", f"{op}: expected a __CFADD__ call"
            assert isinstance(rhs, Expr.Const) and rhs.value_int == 0, f"{op}: expected comparison against 0"

    def test_condnb_logic_is_always_true(self):
        ccall = _make_ccall(AMD64_CondTypes["CondNB"], AMD64_OpTypes["G_CC_OP_LOGICL"])
        result = _rewrite(ccall)
        assert isinstance(result, Expr.Const) and result.value_int == 1
        assert result.bits == ccall.bits


class TestAMD64CCallRewriterCondZCopy(unittest.TestCase):
    """CondZ/CondNZ over G_CC_OP_COPY read ZF straight out of the saved flags."""

    def test_condz_copy_is_true_when_zf_set(self):
        zf = AMD64_CondBitMasks["G_CC_MASK_Z"]
        copy = AMD64_OpTypes["G_CC_OP_COPY"]
        assert _rewritten_value(AMD64_CondTypes["CondZ"], copy, zf, 0) is True
        assert _rewritten_value(AMD64_CondTypes["CondZ"], copy, 0, 0) is False
        assert _rewritten_value(AMD64_CondTypes["CondNZ"], copy, zf, 0) is False
        assert _rewritten_value(AMD64_CondTypes["CondNZ"], copy, 0, 0) is True

    def test_condz_copy_matches_oracle(self):
        copy = AMD64_OpTypes["G_CC_OP_COPY"]
        for cond in ("CondZ", "CondNZ"):
            for flags in range(256):
                assert _rewritten_value(AMD64_CondTypes[cond], copy, flags, 0) == _oracle(
                    AMD64_CondTypes[cond], copy, flags, 0
                ), f"{cond} flags={flags:#x}"


#  Boundary sweep: all 256 values of dep_1 against a fixed spread of dep_2 (zero, small values, the
#  signed/unsigned transitions, the top of the range, and a bit pattern). These are ordering
#  comparisons, so the boundary values cover every transition of the relation under test.
#  A FULL 256x256 sweep (65,536 pairs) was run out-of-tree for every 8-bit cell below -- 0
#  mismatches against ccall.py's executable amd64g_calculate_condition, and independently against a
#  native cmpb/setcc oracle on hardware (CondB x SUBB included as a control; ~200k further control
#  cases on pre-existing rules also clean). The 16/32/64-bit widths are covered by ccall.py and the
#  width-logic tests, not by the hardware oracle. ccall.py alone would be circular -- the rewriter
#  and the oracle share a model. Hardware-harness note: for LOGIC* ops, VEX's cc_dep1 is the
#  RESULT of the operation, not an operand.
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

    def test_condbe_subb_differential(self):
        self._sweep("CondBE", "G_CC_OP_SUBB")

    def test_condb_subb_differential(self):
        self._sweep("CondB", "G_CC_OP_SUBB")

    def test_condnb_subb_differential(self):
        self._sweep("CondNB", "G_CC_OP_SUBB")

    def test_condbe_logicb_differential(self):
        self._sweep("CondBE", "G_CC_OP_LOGICB")

    def test_condb_logicb_differential(self):
        self._sweep("CondB", "G_CC_OP_LOGICB")

    def test_condnb_logicb_differential(self):
        self._sweep("CondNB", "G_CC_OP_LOGICB")

    def test_condnb_addb_differential(self):
        self._sweep("CondNB", "G_CC_OP_ADDB")


class TestAMD64CCallRewriterRealBinaries(unittest.TestCase):
    """Binary-driven regressions for the amd64 ccall rewriter.

    The synthetic tests above feed hand-built ccalls straight to the rewriter. They cannot
    exercise the part of the pipeline that actually needed fixing: the propagator folding
    cc_op/cc_dep across basic blocks so the ccall is even recognizable at rewrite time. When a
    cell is unhandled the rewriter returns None, the callee survives as an undeclared `_ccall`,
    and it reaches the C output. Each function below decompiled to a stray `_ccall(...)` before
    these commits and is clean after; the assertion is simply that no `_ccall(` remains.

    The binaries are real gcc-13.3.0 -O2 objects (stripped) copied into the angr binaries repo.
    A whole-binary CFGFast is required -- region/scoped CFGs do not reproduce these cross-block
    ccall folds. Every target was confirmed stable across 3 repeated decompiles.
    """

    def _assert_no_ccall(self, bin_name, addrs):
        bin_path = os.path.join(test_location, "x86_64", bin_name)
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model, recover_variables=True)
        for addr in addrs:
            func = cfg.functions.get_by_addr(addr)
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
            assert dec.codegen is not None and dec.codegen.text is not None, f"no codegen for {addr:#x}"
            assert "_ccall(" not in dec.codegen.text, f"{addr:#x}: stray _ccall in decompilation"

    def test_file_ccalls_cleared(self):
        # gcc-13.3.0 -O2 `file`. These carry CondBE/CondNB over SUB (unsigned <= / >=) folds;
        # sub_409150 recovers the `v <= 0x200` selector of file_pstring_length_size.
        self._assert_no_ccall(
            "file_gcc13.3.0_O2",
            [0x409150, 0x40C360, 0x4134D0, 0x413630, 0x418BD0, 0x41DD00],
        )

    def test_gzip_ccall_cleared(self):
        # gcc-13.3.0 -O2 `gzip`. sub_409b60 had two ccalls; clearing them flips the function to
        # fully compilable C.
        self._assert_no_ccall("gzip_gcc13.3.0_O2", [0x409B60])


if __name__ == "__main__":
    unittest.main()
