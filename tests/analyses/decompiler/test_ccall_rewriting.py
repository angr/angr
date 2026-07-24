#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

from typing import cast

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import claripy

import angr
from angr.ailment import Expr
from angr.ailment.manager import Manager
from angr.analyses.decompiler.ccall_rewriters.amd64_ccalls import AMD64CCallRewriter
from angr.engines.vex.claripy.ccall import data as ccall_data
from angr.engines.vex.claripy.ccall import pc_calculate_condition
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

AMD64_CondTypes = cast("dict[str, int]", ccall_data["AMD64"]["CondTypes"])
AMD64_OpTypes = cast("dict[str, int]", ccall_data["AMD64"]["OpTypes"])

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
