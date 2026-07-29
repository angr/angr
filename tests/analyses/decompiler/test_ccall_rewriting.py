#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

from typing import Any, cast

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import claripy

import angr
from angr.ailment import Expr
from angr.ailment.manager import Manager
from angr.analyses.decompiler.ccall_rewriters.amd64_ccalls import AMD64CCallRewriter
from angr.engines.vex.claripy.ccall import data, pc_calculate_condition
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

AMD64_CondTypes = cast("dict[str, int]", data["AMD64"]["CondTypes"])
AMD64_OpTypes = cast("dict[str, int]", data["AMD64"]["OpTypes"])
AMD64_CondBitMasks = data["AMD64"]["CondBitMasks"]

# register offsets standing in for the two dependency operands of the ccalls under test
DEP_1_OFFSET = 16
DEP_2_OFFSET = 24


def ail_to_claripy(expr, dep_1, dep_2):
    """
    Evaluate a rewritten AIL expression symbolically, substituting dep_1 and dep_2 for the two
    placeholder registers. Only the node types that the AMD64 ccall rewriter emits are supported;
    anything else raises so that a new kind of rewrite cannot silently go unchecked.
    """
    if isinstance(expr, Expr.Const):
        return claripy.BVV(expr.value_int, expr.bits)

    if isinstance(expr, Expr.Register):
        reg = dep_1 if expr.reg_offset == DEP_1_OFFSET else dep_2
        return reg[expr.bits - 1 : 0]

    if isinstance(expr, Expr.Convert):
        operand = ail_to_claripy(expr.operand, dep_1, dep_2)
        if expr.to_bits < expr.from_bits:
            return operand[expr.to_bits - 1 : 0]
        if expr.to_bits > expr.from_bits:
            extension = expr.to_bits - expr.from_bits
            return operand.sign_extend(extension) if expr.is_signed else operand.zero_extend(extension)
        return operand

    if isinstance(expr, Expr.BinaryOp):
        lhs = ail_to_claripy(expr.operands[0], dep_1, dep_2)
        rhs = ail_to_claripy(expr.operands[1], dep_1, dep_2)
        if expr.op == "Add":
            return lhs + rhs
        if expr.op == "Sub":
            return lhs - rhs
        if expr.op == "And":
            return lhs & rhs
        comparators = {
            "CmpEQ": lambda a, b: a == b,
            "CmpNE": lambda a, b: a != b,
            "CmpLT": claripy.SLT if expr.signed else claripy.ULT,
            "CmpGE": claripy.SGE if expr.signed else claripy.UGE,
        }
        if expr.op in comparators:
            return claripy.If(comparators[expr.op](lhs, rhs), claripy.BVV(1, 1), claripy.BVV(0, 1))
        raise AssertionError(f"Unexpected binary operator {expr.op}")

    raise AssertionError(f"Unexpected expression {expr!r}")


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


class TestAMD64CCallRewriterOracle(unittest.TestCase):
    """
    Check the AMD64 ccall rewriter against pc_calculate_condition(), angr's own implementation of
    amd64g_calculate_condition() and therefore the reference for what each (cond, cc_op) pair means.

    The rewritten expression and the reference are compared symbolically, so a passing check holds
    for every possible pair of operands rather than for a sampled subset.
    """

    def setUp(self):
        self.project = angr.load_shellcode(b"\x90", arch="AMD64")
        self.ail_manager = Manager(arch=self.project.arch)

    def _rewrite(self, cond: int, op: int, dep_2_is_zero: bool = False):
        manager = self.ail_manager
        dep_2 = (
            Expr.Const(manager.next_atom(), 0, 64)
            if dep_2_is_zero
            else Expr.Register(manager.next_atom(), DEP_2_OFFSET, 64)
        )
        ccall = Expr.VEXCCallExpression(
            manager.next_atom(),
            "amd64g_calculate_condition",
            (
                Expr.Const(manager.next_atom(), cond, 64),
                Expr.Const(manager.next_atom(), op, 64),
                Expr.Register(manager.next_atom(), DEP_1_OFFSET, 64),
                dep_2,
                Expr.Const(manager.next_atom(), 0, 64),
            ),
            bits=64,
        )
        return AMD64CCallRewriter(ccall, self.project, manager).result

    def _assert_matches_oracle(self, cond: int, op: int, dep_2_is_zero: bool = False):
        rewritten = self._rewrite(cond, op, dep_2_is_zero=dep_2_is_zero)
        assert rewritten is not None, f"cond={cond} cc_op={op} was not rewritten"

        dep_1 = claripy.BVS("dep_1", 64, explicit_name=True)
        dep_2 = claripy.BVV(0, 64) if dep_2_is_zero else claripy.BVS("dep_2", 64, explicit_name=True)
        expected = pc_calculate_condition(
            None, claripy.BVV(cond, 64), claripy.BVV(op, 64), dep_1, dep_2, claripy.BVV(0, 64), platform="AMD64"
        )

        solver = claripy.Solver()
        solver.add(expected != ail_to_claripy(rewritten, dep_1, dep_2))
        assert not solver.satisfiable(), f"cond={cond} cc_op={op} does not match pc_calculate_condition()"

    def test_conds_over_sub(self):
        # CondNS over SUB is not implemented: no real binary reads SF back that way
        for width in ("B", "W", "L", "Q"):
            self._assert_matches_oracle(AMD64_CondTypes["CondS"], AMD64_OpTypes[f"G_CC_OP_SUB{width}"])

    def test_conds_condns_over_add(self):
        for width in ("B", "W", "L", "Q"):
            for cond in ("CondS", "CondNS"):
                self._assert_matches_oracle(AMD64_CondTypes[cond], AMD64_OpTypes[f"G_CC_OP_ADD{width}"])

    def test_conds_condns_over_logic(self):
        for width in ("B", "W", "L", "Q"):
            for cond in ("CondS", "CondNS"):
                self._assert_matches_oracle(
                    AMD64_CondTypes[cond], AMD64_OpTypes[f"G_CC_OP_LOGIC{width}"], dep_2_is_zero=True
                )

    def test_condz_condnz_over_add(self):
        for width in ("B", "W", "L", "Q"):
            for cond in ("CondZ", "CondNZ"):
                self._assert_matches_oracle(AMD64_CondTypes[cond], AMD64_OpTypes[f"G_CC_OP_ADD{width}"])

    def test_condp_condnp_over_copy(self):
        for cond in ("CondP", "CondNP"):
            self._assert_matches_oracle(AMD64_CondTypes[cond], AMD64_OpTypes["G_CC_OP_COPY"])

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
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x53F6C0, run_ccc=False)
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
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x40CC10, extra_func_addrs=[0x4888A0], run_ccc=False)

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


class TestAMD64PureComparisonCCallsOnBinaries(unittest.TestCase):
    """
    Check that the pure-comparison conditions no longer leak into decompilation output as
    uncompilable _ccall() expressions.
    """

    def test_luac_parity_over_copy(self):
        # this function compares doubles with ucomisd, which leaves the resulting flags in cc_dep1
        # with cc_op == G_CC_OP_COPY, and then branches on PF
        bin_path = os.path.join(test_location, "x86_64", "luac_gcc13.3.0_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)

        dec = proj.analyses.Decompiler(cfg.functions[0x41C710], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "_ccall" not in dec.codegen.text

    def test_static_sign_over_add(self):
        # jns at 0x41069e, and cmovns right after an add at 0x4678b7 and at 0x489a8e: SF is read off
        # the result of an add, which libVEX's spec helper does not resolve
        bin_path = os.path.join(test_location, "x86_64", "static")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)

        for addr in (0x410330, 0x467860, 0x488960):
            dec = proj.analyses.Decompiler(cfg.functions[addr], cfg=cfg)
            assert dec.codegen is not None and dec.codegen.text is not None
            assert "_ccall" not in dec.codegen.text, f"{addr:#x} still contains an unlifted ccall"

    def test_luac_zero_over_add(self):
        # 0x405cee branches on ZF over an 8-bit add and 0x405f87 on ZF over a 64-bit add; the
        # function also branches on CondLE over an add, which is not a pure comparison and still
        # leaves an _ccall() behind, so only the ZF cells are checked here
        bin_path = os.path.join(test_location, "x86_64", "luac_gcc13.3.0_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)

        dec = proj.analyses.Decompiler(cfg.functions[0x405B20], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        remaining = {(int(cond), int(op)) for cond, op in re.findall(r"_ccall\(\s*(\d+),\s*(\d+)", dec.codegen.text)}
        for cond, op in (
            (AMD64_CondTypes["CondZ"], AMD64_OpTypes["G_CC_OP_ADDB"]),
            (AMD64_CondTypes["CondNZ"], AMD64_OpTypes["G_CC_OP_ADDQ"]),
        ):
            assert (cond, op) not in remaining, f"cond={cond} cc_op={op} still leaked into the decompilation"

    def test_lighttpd_sign_and_zero_over_add_and_sub(self):
        # lighttpd 1.4.76 built with gcc 17.0.0 at -O2. Four functions, four widths, all of which
        # decompile completely clean once the pure comparisons are rewritten:
        #   pcre_keyvalue_buffer_process  SF over a 32-bit add at 0x4d1b8b
        #   http_response_parse_headers   SF and ZF over a 64-bit add at 0x52d3a2 and 0x52d3a8
        #   fcgi_recv_parse               SF over a 16-bit subtraction at 0x4ad8a2
        #   fdevent_load_file             ZF over a 64-bit add at 0x45b3d5
        bin_path = os.path.join(test_location, "x86_64", "lighttpd_gcc17.0.0_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)

        for addr, size in ((0x4D1660, 0xD6C), (0x52C600, 0x1693), (0x4AD440, 0xA69), (0x45B1E4, 0x892)):
            cfg = proj.analyses.CFGFast(
                fail_fast=True, normalize=True, regions=[(addr, addr + size + 0x80)], function_starts=[addr]
            )
            dec = proj.analyses.Decompiler(cfg.functions[addr], cfg=cfg)
            assert dec.codegen is not None and dec.codegen.text is not None
            assert "_ccall" not in dec.codegen.text, f"{addr:#x} still contains an unlifted ccall"

    def test_cvs_sign_over_sub(self):
        # build_charclass.isra.0 reads SF off a 16-bit subtraction at 0x47cbc0. The function also
        # branches on CondNBE over LOGIC and over COPY, which are unrelated conditions and still
        # leave an _ccall() behind, so only the SF cell is checked here.
        bin_path = os.path.join(test_location, "x86_64", "cvs")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            fail_fast=True, normalize=True, regions=[(0x47C6A0, 0x47C6A0 + 0x2080)], function_starts=[0x47C6A0]
        )

        dec = proj.analyses.Decompiler(cfg.functions[0x47C6A0], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        remaining = {(int(cond), int(op)) for cond, op in re.findall(r"_ccall\(\s*(\d+),\s*(\d+)", dec.codegen.text)}
        cell = (AMD64_CondTypes["CondS"], AMD64_OpTypes["G_CC_OP_SUBW"])
        assert cell not in remaining, "CondS over SUBW still leaked into the decompilation"


if __name__ == "__main__":
    unittest.main()
