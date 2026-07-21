#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

from typing import Any, cast

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.ailment import Expr, Manager
from angr.analyses.decompiler.ccall_rewriters.amd64_ccalls import AMD64CCallRewriter
from angr.engines.vex.claripy.ccall import data
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

AMD64_CondTypes = cast("dict[str, int]", data["AMD64"]["CondTypes"])
AMD64_OpTypes = cast("dict[str, int]", data["AMD64"]["OpTypes"])
AMD64_CondBitMasks = data["AMD64"]["CondBitMasks"]


def _rewrite_amd64_cond(cond_v, op_v, dep_1=None, dep_2=None, bits=64) -> Any:
    """Build an amd64g_calculate_condition ccall and run the AMD64 rewriter on it."""
    if dep_1 is None:
        dep_1 = Expr.Register(1, 16, 64)
    if dep_2 is None:
        dep_2 = Expr.Register(2, 24, 64)
    ccall = Expr.VEXCCallExpression(
        idx=0,
        callee="amd64g_calculate_condition",
        operands=(
            Expr.Const(0, cond_v, 64),
            Expr.Const(0, op_v, 64),
            dep_1,
            dep_2,
            Expr.Const(0, 0, 64),
        ),
        bits=bits,
    )
    proj = angr.load_shellcode(b"\x90", arch="AMD64")
    return AMD64CCallRewriter(ccall, proj, Manager()).result


def _unwrap_convert(expr):
    """Strip an outer Convert wrapper if present."""
    if isinstance(expr, Expr.Convert):
        return expr.operand
    return expr


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


class TestAMD64CondOverflowRewriting(unittest.TestCase):
    """Rewriting of the CondO / CondNO (jo / jno) family for amd64g_calculate_condition."""

    # ---- LOGIC: and/or/xor always clear OF ----

    def test_logic_o_is_false(self):
        for op in ("G_CC_OP_LOGICB", "G_CC_OP_LOGICW", "G_CC_OP_LOGICL", "G_CC_OP_LOGICQ"):
            result = _rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes[op])
            assert isinstance(result, Expr.Const), op
            assert result.value_int == 0, op
            assert result.bits == 64, op

    def test_logic_no_is_true(self):
        for op in ("G_CC_OP_LOGICB", "G_CC_OP_LOGICW", "G_CC_OP_LOGICL", "G_CC_OP_LOGICQ"):
            result = _rewrite_amd64_cond(AMD64_CondTypes["CondNO"], AMD64_OpTypes[op])
            assert isinstance(result, Expr.Const), op
            assert result.value_int == 1, op

    # ---- ADD / SUB: signed overflow helpers ----

    def test_add_o_emits_ofadd(self):
        for op in ("G_CC_OP_ADDB", "G_CC_OP_ADDW", "G_CC_OP_ADDL", "G_CC_OP_ADDQ"):
            result = _rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes[op])
            assert isinstance(result, Expr.Call), op
            assert result.target == "__OFADD__", op
            assert len(result.args) == 2, op
            assert result.bits == 64, op

    def test_sub_o_emits_ofsub(self):
        for op in ("G_CC_OP_SUBB", "G_CC_OP_SUBW", "G_CC_OP_SUBL", "G_CC_OP_SUBQ"):
            result = _rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes[op])
            assert isinstance(result, Expr.Call), op
            assert result.target == "__OFSUB__", op

    def test_add_no_negates_ofadd(self):
        result = _rewrite_amd64_cond(AMD64_CondTypes["CondNO"], AMD64_OpTypes["G_CC_OP_ADDQ"])
        inner = _unwrap_convert(result)
        assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpEQ"
        assert isinstance(inner.operands[0], Expr.Call) and inner.operands[0].target == "__OFADD__"
        assert isinstance(inner.operands[1], Expr.Const) and inner.operands[1].value_int == 0
        assert result.bits == 64

    def test_sub_no_negates_ofsub(self):
        result = _rewrite_amd64_cond(AMD64_CondTypes["CondNO"], AMD64_OpTypes["G_CC_OP_SUBQ"])
        inner = _unwrap_convert(result)
        assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpEQ"
        assert isinstance(inner.operands[0], Expr.Call) and inner.operands[0].target == "__OFSUB__"

    def test_add_operands_narrowed_to_op_width(self):
        # the byte form must narrow both operands to 8 bits
        result = _rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes["G_CC_OP_ADDB"])
        assert all(arg.bits == 8 for arg in result.args)

    # ---- UMUL / SMUL: multiply overflow helpers ----

    def test_umul_o_emits_ofumul(self):
        for op in ("G_CC_OP_UMULB", "G_CC_OP_UMULW", "G_CC_OP_UMULL", "G_CC_OP_UMULQ"):
            result = _rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes[op])
            assert isinstance(result, Expr.Call), op
            assert result.target == "__OFUMUL__", op

    def test_smul_o_emits_ofsmul(self):
        for op in ("G_CC_OP_SMULB", "G_CC_OP_SMULW", "G_CC_OP_SMULL", "G_CC_OP_SMULQ"):
            result = _rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes[op])
            assert isinstance(result, Expr.Call), op
            assert result.target == "__OFSMUL__", op

    def test_umul_no_negates_ofumul(self):
        result = _rewrite_amd64_cond(AMD64_CondTypes["CondNO"], AMD64_OpTypes["G_CC_OP_UMULQ"])
        inner = _unwrap_convert(result)
        assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpEQ"
        assert isinstance(inner.operands[0], Expr.Call) and inner.operands[0].target == "__OFUMUL__"

    def test_umul_operands_narrowed_to_op_width(self):
        result = _rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes["G_CC_OP_UMULW"])
        assert all(arg.bits == 16 for arg in result.args)

    # ---- INC / DEC: overflow only at the signed extremes ----

    def test_inc_o_compares_against_signed_min(self):
        for op, nbits in (
            ("G_CC_OP_INCB", 8),
            ("G_CC_OP_INCW", 16),
            ("G_CC_OP_INCL", 32),
            ("G_CC_OP_INCQ", 64),
        ):
            inner = _unwrap_convert(_rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes[op]))
            assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpEQ", op
            assert inner.operands[1].value_int == 1 << (nbits - 1), op

    def test_inc_no_is_inverted(self):
        inner = _unwrap_convert(_rewrite_amd64_cond(AMD64_CondTypes["CondNO"], AMD64_OpTypes["G_CC_OP_INCQ"]))
        assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpNE"

    def test_dec_o_compares_against_signed_max(self):
        for op, nbits in (
            ("G_CC_OP_DECB", 8),
            ("G_CC_OP_DECW", 16),
            ("G_CC_OP_DECL", 32),
            ("G_CC_OP_DECQ", 64),
        ):
            inner = _unwrap_convert(_rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes[op]))
            assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpEQ", op
            assert inner.operands[1].value_int == (1 << (nbits - 1)) - 1, op

    def test_dec_no_is_inverted(self):
        inner = _unwrap_convert(_rewrite_amd64_cond(AMD64_CondTypes["CondNO"], AMD64_OpTypes["G_CC_OP_DECB"]))
        assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpNE"

    # ---- COPY: test the stored OF bit ----

    def test_copy_o_masks_of_bit(self):
        inner = _unwrap_convert(_rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes["G_CC_OP_COPY"]))
        assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpNE"
        masked = inner.operands[0]
        assert isinstance(masked, Expr.BinaryOp) and masked.op == "And"
        assert masked.operands[1].value_int == AMD64_CondBitMasks["G_CC_MASK_O"]

    def test_copy_no_masks_of_bit(self):
        inner = _unwrap_convert(_rewrite_amd64_cond(AMD64_CondTypes["CondNO"], AMD64_OpTypes["G_CC_OP_COPY"]))
        assert isinstance(inner, Expr.BinaryOp) and inner.op == "CmpEQ"

    # ---- guards ----

    def test_symbolic_cond_returns_none(self):
        ccall = Expr.VEXCCallExpression(
            idx=0,
            callee="amd64g_calculate_condition",
            operands=(
                Expr.Register(0, 0, 64),  # non-constant cond
                Expr.Const(0, AMD64_OpTypes["G_CC_OP_UMULQ"], 64),
                Expr.Register(1, 16, 64),
                Expr.Register(2, 24, 64),
                Expr.Const(0, 0, 64),
            ),
            bits=64,
        )
        proj = angr.load_shellcode(b"\x90", arch="AMD64")
        assert AMD64CCallRewriter(ccall, proj, Manager()).result is None

    def test_symbolic_op_returns_none(self):
        ccall = Expr.VEXCCallExpression(
            idx=0,
            callee="amd64g_calculate_condition",
            operands=(
                Expr.Const(0, AMD64_CondTypes["CondO"], 64),
                Expr.Register(0, 0, 64),  # non-constant cc_op
                Expr.Register(1, 16, 64),
                Expr.Register(2, 24, 64),
                Expr.Const(0, 0, 64),
            ),
            bits=64,
        )
        proj = angr.load_shellcode(b"\x90", arch="AMD64")
        assert AMD64CCallRewriter(ccall, proj, Manager()).result is None

    def test_unhandled_op_returns_none(self):
        # shifts do not have a CondO arm
        result = _rewrite_amd64_cond(AMD64_CondTypes["CondO"], AMD64_OpTypes["G_CC_OP_SHLQ"])
        assert result is None


class TestAMD64CondOverflowBinary(unittest.TestCase):
    """Real-binary regression: no OF ccall may leak into the decompilation."""

    def test_gzip_overflow_checks_have_no_ccall(self):
        # gzip has a size-computation helper guarded by jo on ADDQ and SMULQ
        bin_path = os.path.join(test_location, "x86_64", "gzip_gcc13.3.0_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions[0x40F1B0], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "_ccall" not in dec.codegen.text
        assert "__OFADD__" in dec.codegen.text
        assert "__OFSMUL__" in dec.codegen.text

    def test_file_overflow_checks_have_no_ccall(self):
        # file has several allocation helpers guarded by jo on UMULQ
        bin_path = os.path.join(test_location, "x86_64", "file_gcc13.3.0_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)
        for addr in (0x41E520, 0x41E5A0, 0x41EED0):
            dec = proj.analyses.Decompiler(cfg.functions[addr], cfg=cfg)
            assert dec.codegen is not None and dec.codegen.text is not None
            assert "_ccall" not in dec.codegen.text, f"{addr:#x} still leaks a ccall"
            assert "__OFUMUL__" in dec.codegen.text, f"{addr:#x} lost its overflow check"

    def test_tar_umul_overflow_check_is_rewritten(self):
        # tar guards a multiply with `mul %rbp` @ 0x53f77e / `jno` @ 0x53f784.
        # The jno is canonicalized into CondO with an inverted branch, so the ccall
        # reaching the rewriter is CondO x UMULQ (48), constant cc_op.
        # This function also keeps ccalls from cc_op families outside this rewrite,
        # so only the OF conditions are asserted -- the rewrite must be surgical.
        bin_path = os.path.join(test_location, "x86_64", "tar_gcc17_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions[0x53F6C0], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "__OFUMUL__" in dec.codegen.text
        assert "_ccall(0, " not in dec.codegen.text
        assert "_ccall(1, " not in dec.codegen.text

    def test_coreutils_cat_overflow_checks_have_no_ccall(self):
        # coreutils' xalloc idiom. Verified cc_op values, all constant:
        #   main    @ 0x4023c0 -- CondO x SMULQ (52) and CondO x ADDQ (4)
        #   xpalloc @ 0x41f470 -- CondO x ADDQ (4) and CondO x SMULQ (52)
        bin_path = os.path.join(test_location, "x86_64", "cat_gcc17.0.0_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)
        for addr in (0x4023C0, 0x41F470):
            dec = proj.analyses.Decompiler(cfg.functions[addr], cfg=cfg)
            assert dec.codegen is not None and dec.codegen.text is not None
            assert "_ccall" not in dec.codegen.text, f"{addr:#x} still leaks a ccall"
            assert "__OFSMUL__" in dec.codegen.text, f"{addr:#x} lost its overflow check"
            assert "__OFADD__" in dec.codegen.text, f"{addr:#x} lost its overflow check"

    def test_grep_overflow_checks_have_no_ccall(self):
        # Verified cc_op values, all constant:
        #   fillbuf    @ 0x40cc10 -- CondO x ADDQ (4), 2 sites
        #   xstrtoimax @ 0x4888a0 -- CondO x SMULQ (52), 14 sites
        bin_path = os.path.join(test_location, "x86_64", "grep_gcc17.0.0_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)

        dec = proj.analyses.Decompiler(cfg.functions[0x40CC10], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "_ccall" not in dec.codegen.text
        assert "__OFADD__" in dec.codegen.text

        dec = proj.analyses.Decompiler(cfg.functions[0x4888A0], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "_ccall" not in dec.codegen.text
        assert "__OFSMUL__" in dec.codegen.text

    def test_zlib_minigzip_umul_overflow_has_no_ccall(self):
        # zlib guards its gz buffer sizing with an unsigned multiply. Verified
        # cc_op values, all constant:
        #   gzfread  @ 0x40ea40 -- CondO x UMULQ (48)
        #   gzfwrite @ 0x413d50 -- CondO x UMULQ (48)
        bin_path = os.path.join(test_location, "x86_64", "minigzip_gcc17.0.0_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)
        for addr in (0x40EA40, 0x413D50):
            dec = proj.analyses.Decompiler(cfg.functions[addr], cfg=cfg)
            assert dec.codegen is not None and dec.codegen.text is not None
            assert "_ccall" not in dec.codegen.text, f"{addr:#x} still leaks a ccall"
            assert "__OFUMUL__" in dec.codegen.text, f"{addr:#x} lost its overflow check"


if __name__ == "__main__":
    unittest.main()
