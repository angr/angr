#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.ailment import Expr, Manager
from angr.analyses.decompiler.ccall_rewriters.amd64_ccalls import AMD64CCallRewriter
from angr.engines.vex.claripy.ccall import data
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


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


class TestAMD64CCallRewriterDecWidth(unittest.TestCase):
    """CondZ/CondNZ over DEC must compare only the low nbits of the result.

    ZF for dec on a sub-register is computed from that sub-register alone: for
    dec al with rax == 0x101 the hardware sets ZF (al becomes 0), but a
    full-width compare tests 0x100 == 0 and takes the wrong branch.
    """

    def _rewrite(self, cond, op, dep1_value):
        cond_v = data["AMD64"]["CondTypes"][cond]
        op_v = data["AMD64"]["OpTypes"][op]
        assert cond_v is not None and op_v is not None
        ccall = Expr.VEXCCallExpression(
            idx=0,
            callee="amd64g_calculate_condition",
            operands=(
                Expr.Const(0, cond_v, 64),
                Expr.Const(0, op_v, 64),
                Expr.Const(1, dep1_value, 64),
                Expr.Const(2, 0, 64),
                Expr.Const(3, 0, 64),
            ),
            bits=64,
        )
        proj = angr.load_shellcode(b"\x90", arch="AMD64")
        return AMD64CCallRewriter(ccall, proj, Manager(arch=proj.arch)).result

    def test_condz_dec_narrows_to_op_width(self):
        for op, bits in (("G_CC_OP_DECB", 8), ("G_CC_OP_DECW", 16), ("G_CC_OP_DECL", 32), ("G_CC_OP_DECQ", 64)):
            for cond in ("CondZ", "CondNZ"):
                result = self._rewrite(cond, op, 1 << bits if bits < 64 else 1)
                assert isinstance(result, Expr.Convert)
                cmp = result.operand  # strip the Convert back to ccall.bits
                lhs = cmp.operands[0]
                assert lhs.bits == bits, f"{cond} x {op}: operand is {lhs.bits}-bit, expected {bits}"

    def test_condz_decb_ignores_upper_bits(self):
        # result low byte is 0 (ZF set) while bits above it are non-zero
        result = self._rewrite("CondZ", "G_CC_OP_DECB", 0x100)
        assert isinstance(result, Expr.Convert)
        cmp = result.operand
        assert cmp.op == "CmpEQ"
        lhs, rhs = cmp.operands
        assert lhs.value_int == 0 and lhs.bits == 8  # 0x100 truncated to its low byte
        assert rhs.value_int == 0


if __name__ == "__main__":
    unittest.main()
