#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
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


class TestAMD64RflagsCAddCarry(unittest.TestCase):
    """The rflags_c ADD arm must compute CF as (a + b) <u a -- strict, per VEX's pc_actions_ADD.

    A non-strict <=u misreads CF as 1 whenever the addend is zero (res == a), e.g. add rax, 0.
    """

    def _rewrite(self, op_name, dep1_value, dep2_value):
        from angr.ailment import Expr, Manager
        from angr.analyses.decompiler.ccall_rewriters.amd64_ccalls import AMD64CCallRewriter
        from angr.engines.vex.claripy.ccall import data

        op_v = data["AMD64"]["OpTypes"][op_name]
        ccall = Expr.VEXCCallExpression(
            idx=0,
            callee="amd64g_calculate_rflags_c",
            operands=(
                Expr.Const(0, op_v, 64),
                Expr.Const(1, dep1_value, 64),
                Expr.Const(2, dep2_value, 64),
                Expr.Const(3, 0, 64),
            ),
            bits=64,
        )
        proj = angr.load_shellcode(b"\x90", arch="AMD64")
        return AMD64CCallRewriter(ccall, proj, Manager(arch=proj.arch)).result

    @staticmethod
    def _eval_cf(expr):
        """Concretely evaluate the rewritten ITE with Const operands."""
        from angr.ailment import Expr

        def mask(v, b):
            return v & ((1 << b) - 1)

        def ev(e):
            if isinstance(e, Expr.Const):
                return mask(e.value_int, e.bits), e.bits
            if isinstance(e, Expr.Convert):
                v, _ = ev(e.operand)
                return mask(v, e.to_bits), e.to_bits
            if isinstance(e, Expr.ITE):
                c, _ = ev(e.cond)
                return ev(e.iftrue) if c else ev(e.iffalse)
            if isinstance(e, Expr.BinaryOp):
                a, ab = ev(e.operands[0])
                b, bb = ev(e.operands[1])
                bits = max(ab, bb)
                if e.op == "CmpLT":
                    return int(a < b), 1
                if e.op == "CmpLE":
                    return int(a <= b), 1
                if e.op == "Add":
                    return mask(a + b, bits), bits
                raise NotImplementedError(e.op)
            raise NotImplementedError(type(e))

        return ev(expr)[0] & 1

    def test_add_zero_addend_has_no_carry(self):
        # add x, 0 never carries; the non-strict comparison read CF=1 here
        for op in ("G_CC_OP_ADDB", "G_CC_OP_ADDW", "G_CC_OP_ADDL", "G_CC_OP_ADDQ"):
            result = self._rewrite(op, 0x41, 0)
            assert result is not None, f"{op}: not rewritten"
            assert self._eval_cf(result) == 0, f"{op}: CF must be 0 for a zero addend"

    def test_add_carry_matches_vex_ult(self):
        import claripy

        from angr.engines.vex.claripy.ccall import amd64g_calculate_rflags_c, data

        op_v = data["AMD64"]["OpTypes"]["G_CC_OP_ADDB"]
        # boundary sample: full dep1 range against carry/no-carry boundary addends
        for dep1 in range(256):
            for dep2 in (0, 1, 0x7F, 0x80, 0xFE, 0xFF):
                got = self._eval_cf(self._rewrite("G_CC_OP_ADDB", dep1, dep2))
                want = (
                    claripy.backends.concrete.eval(
                        amd64g_calculate_rflags_c(
                            None,
                            claripy.BVV(op_v, 64),
                            claripy.BVV(dep1, 64),
                            claripy.BVV(dep2, 64),
                            claripy.BVV(0, 64),
                        ),
                        1,
                    )[0]
                    & 1
                )
                assert got == want, f"ADDB dep1={dep1:#x} dep2={dep2:#x}: CF {got} != {want}"


if __name__ == "__main__":
    unittest.main()
