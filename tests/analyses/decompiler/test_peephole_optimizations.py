#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr import ailment
from angr.ailment.expression import BinaryOp, Const
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import CmpMaskedShift, ConstantDereferences, EagerEvaluation
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestPeepholeOptimizations(unittest.TestCase):
    def test_constant_dereference(self):
        # a = *(A) :=> a = the variable at at A iff
        # - A is a pointer that points to a read-only section.

        proj = angr.Project(os.path.join(test_location, "armel", "decompiler", "rm"), auto_load_libs=False)

        expr = ailment.Expr.Load(
            None,
            ailment.Expr.Const(None, 0xA000, proj.arch.bits),
            proj.arch.bytes,
            archinfo.Endness.LE,
            ins_addr=0x400100,
        )
        manager = Manager()
        opt = ConstantDereferences(proj, proj.kb, manager, 0)
        optimized = opt.optimize(expr)
        assert isinstance(optimized, ailment.Const)
        assert optimized.value == 0x183F8
        assert optimized.tags.get("ins_addr", None) == 0x400100, "Peephole optimizer lost tags."

        # multiple cases that no optimization should happen
        # a. Loading a pointer from a writable location
        expr = ailment.Expr.Load(None, ailment.Expr.Const(None, 0x21DF4, proj.arch.bits), 1, archinfo.Endness.LE)
        opt = ConstantDereferences(proj, proj.kb, manager, 0)
        optimized = opt.optimize(expr)
        assert optimized is None

    def test_eager_eval_mod(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")

        manager = Manager()
        opt = EagerEvaluation(proj, proj.kb, manager)

        # Optimize 12 % 5 --> 2
        expr = BinaryOp(None, "Mod", [Const(None, 12, 32), Const(None, 5, 32)])
        expr_opt = opt.optimize(expr)
        assert isinstance(expr_opt, Const)
        assert expr_opt.value == 2

        # Don't optimize x % 0
        expr = BinaryOp(None, "Mod", [Const(None, 12, 32), Const(None, 0, 32)])
        expr_opt = opt.optimize(expr)
        assert expr_opt is None

    def test_cmp_masked_shift(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = CmpMaskedShift(proj, proj.kb, manager)

        x = ailment.Expr.Register(None, 0, 32)

        # Convert(32->28, x >> 4) == 0x184d2a5  ==>  (x & 0xfffffff0) == 0x184d2a50
        shr = BinaryOp(None, "Shr", [x, Const(None, 4, 32)], False, bits=32)
        conv = ailment.Expr.Convert(None, 32, 28, False, shr)
        expr = BinaryOp(None, "CmpEQ", [conv, Const(None, 0x184D2A5, 28)], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpEQ"
        and_expr, rhs = out.operands
        assert isinstance(and_expr, BinaryOp) and and_expr.op == "And"
        assert isinstance(and_expr.operands[1], Const) and and_expr.operands[1].value == 0xFFFFFFF0
        assert isinstance(rhs, Const) and rhs.value == 0x184D2A50

        # bare (x >> 8) != 0x12  ==>  (x & 0xffffff00) != 0x1200
        shr = BinaryOp(None, "Shr", [x, Const(None, 8, 32)], False, bits=32)
        expr = BinaryOp(None, "CmpNE", [shr, Const(None, 0x12, 32)], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpNE"
        and_expr, rhs = out.operands
        assert and_expr.operands[1].value == 0xFFFFFF00
        assert rhs.value == 0x1200

        # n == 0 (low-mask / cast case) is left alone
        expr = BinaryOp(
            None,
            "CmpEQ",
            [BinaryOp(None, "Shr", [x, Const(None, 0, 32)], False, bits=32), Const(None, 5, 32)],
            False,
            bits=1,
        )
        assert opt.optimize(expr) is None

        # arithmetic shift (Sar) is left alone
        sar = BinaryOp(None, "Sar", [x, Const(None, 4, 32)], True, bits=32)
        expr = BinaryOp(None, "CmpEQ", [sar, Const(None, 5, 28)], False, bits=1)
        assert opt.optimize(expr) is None

        # constant too wide for the compared width: not this pattern
        conv = ailment.Expr.Convert(
            None, 32, 28, False, BinaryOp(None, "Shr", [x, Const(None, 4, 32)], False, bits=32)
        )
        expr = BinaryOp(None, "CmpEQ", [conv, Const(None, 1 << 28, 32)], False, bits=1)
        assert opt.optimize(expr) is None


if __name__ == "__main__":
    unittest.main()
