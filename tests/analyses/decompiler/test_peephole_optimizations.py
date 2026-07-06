#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr import ailment
from angr.ailment.expression import BinaryOp, Const, Convert, Register
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import (
    EXPR_OPTS,
    CmpMaskedShift,
    CmpSubConst,
    ConstantDereferences,
    EagerEvaluation,
    OptimizedDivisionSimplifier,
)
from angr.analyses.decompiler.utils import peephole_optimize_expr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestPeepholeOptimizations(unittest.TestCase):
    def test_constant_dereference(self):
        # a = *(A) :=> a = the variable at at A iff
        # - A is a pointer that points to a read-only section.

        proj = angr.Project(os.path.join(test_location, "armel", "decompiler", "rm"), auto_load_libs=False)
        manager = Manager()

        expr = ailment.Expr.Load(
            manager.next_atom(),
            ailment.Expr.Const(manager.next_atom(), 0xA000, proj.arch.bits),
            proj.arch.bytes,
            archinfo.Endness.LE,
            ins_addr=0x400100,
        )
        opt = ConstantDereferences(proj, proj.kb, manager, 0)
        optimized = opt.optimize(expr)
        assert isinstance(optimized, ailment.Const)
        assert optimized.value == 0x183F8
        assert optimized.tags.get("ins_addr", None) == 0x400100, "Peephole optimizer lost tags."

        # multiple cases that no optimization should happen
        # a. Loading a pointer from a writable location
        expr = ailment.Expr.Load(
            manager.next_atom(),
            ailment.Expr.Const(manager.next_atom(), 0x21DF4, proj.arch.bits),
            1,
            archinfo.Endness.LE,
        )
        opt = ConstantDereferences(proj, proj.kb, manager, 0)
        optimized = opt.optimize(expr)
        assert optimized is None

    def test_eager_eval_mod(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")

        manager = Manager()
        opt = EagerEvaluation(proj, proj.kb, manager)

        # Optimize 12 % 5 --> 2
        expr = BinaryOp(
            manager.next_atom(), "Mod", [Const(manager.next_atom(), 12, 32), Const(manager.next_atom(), 5, 32)]
        )
        expr_opt = opt.optimize(expr)
        assert isinstance(expr_opt, Const)
        assert expr_opt.value == 2

        # Don't optimize x % 0
        expr = BinaryOp(
            manager.next_atom(), "Mod", [Const(manager.next_atom(), 12, 32), Const(manager.next_atom(), 0, 32)]
        )
        expr_opt = opt.optimize(expr)
        assert expr_opt is None

    def test_cmp_masked_shift(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = CmpMaskedShift(proj, proj.kb, manager)

        x = ailment.Expr.Register(manager.next_atom(), 0, 32)

        # Convert(32->28, x >> 4) == 0x184d2a5  ==>  (x & 0xfffffff0) == 0x184d2a50
        shr = BinaryOp(manager.next_atom(), "Shr", [x, Const(manager.next_atom(), 4, 32)], False, bits=32)
        conv = ailment.Expr.Convert(manager.next_atom(), 32, 28, False, shr)
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [conv, Const(manager.next_atom(), 0x184D2A5, 28)], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpEQ"
        and_expr, rhs = out.operands
        assert isinstance(and_expr, BinaryOp) and and_expr.op == "And"
        assert isinstance(and_expr.operands[1], Const) and and_expr.operands[1].value == 0xFFFFFFF0
        assert isinstance(rhs, Const) and rhs.value == 0x184D2A50

        # bare (x >> 8) != 0x12  ==>  (x & 0xffffff00) != 0x1200
        shr = BinaryOp(manager.next_atom(), "Shr", [x, Const(manager.next_atom(), 8, 32)], False, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpNE", [shr, Const(manager.next_atom(), 0x12, 32)], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpNE"
        and_expr, rhs = out.operands
        assert isinstance(and_expr, BinaryOp) and and_expr.op == "And"
        assert isinstance(and_expr.operands[1], Const)
        assert and_expr.operands[1].value == 0xFFFFFF00
        assert isinstance(rhs, Const) and rhs.value == 0x1200

        # n == 0 (low-mask / cast case) is left alone
        expr = BinaryOp(
            manager.next_atom(),
            "CmpEQ",
            [
                BinaryOp(manager.next_atom(), "Shr", [x, Const(manager.next_atom(), 0, 32)], False, bits=32),
                Const(manager.next_atom(), 5, 32),
            ],
            False,
            bits=1,
        )
        assert opt.optimize(expr) is None

        # arithmetic shift (Sar) is left alone
        sar = BinaryOp(manager.next_atom(), "Sar", [x, Const(manager.next_atom(), 4, 32)], True, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [sar, Const(manager.next_atom(), 5, 28)], False, bits=1)
        assert opt.optimize(expr) is None

        # constant too wide for the compared width: not this pattern
        conv = ailment.Expr.Convert(
            manager.next_atom(),
            32,
            28,
            False,
            BinaryOp(manager.next_atom(), "Shr", [x, Const(manager.next_atom(), 4, 32)], False, bits=32),
        )
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [conv, Const(manager.next_atom(), 1 << 28, 32)], False, bits=1)
        assert opt.optimize(expr) is None

    def test_cmp_sub_const(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = CmpSubConst(proj, proj.kb, manager)

        x = ailment.Expr.Register(manager.next_atom(), 0, 32)

        # (x - 50) == 0  ==>  x == 50
        sub = BinaryOp(manager.next_atom(), "Sub", [x, Const(manager.next_atom(), 50, 32)], False, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [sub, Const(manager.next_atom(), 0, 32)], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpEQ"
        assert out.operands[0] == x
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 50

        # (x - 1) != 1  ==>  x != 2
        sub = BinaryOp(manager.next_atom(), "Sub", [x, Const(manager.next_atom(), 1, 32)], False, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpNE", [sub, Const(manager.next_atom(), 1, 32)], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpNE"
        assert out.operands[0] == x
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 2

        # (x + 5) == 12  ==>  x == 7
        add = BinaryOp(manager.next_atom(), "Add", [x, Const(manager.next_atom(), 5, 32)], False, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [add, Const(manager.next_atom(), 12, 32)], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpEQ"
        assert out.operands[0] == x
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 7

        # (50 - x) == 0  ==>  x == 50  (constant minus variable)
        sub = BinaryOp(manager.next_atom(), "Sub", [Const(manager.next_atom(), 50, 32), x], False, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [sub, Const(manager.next_atom(), 0, 32)], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpEQ"
        assert out.operands[0] == x
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 50

        # the compared constant on the left is also handled: 0 == (x - 7) => x == 7
        sub = BinaryOp(manager.next_atom(), "Sub", [x, Const(manager.next_atom(), 7, 32)], False, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [Const(manager.next_atom(), 0, 32), sub], False, bits=1)
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpEQ"
        assert out.operands[0] == x
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 7

        # ordered comparisons must NOT be folded (unsound under wraparound)
        sub = BinaryOp(manager.next_atom(), "Sub", [x, Const(manager.next_atom(), 1, 32)], False, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpLT", [sub, Const(manager.next_atom(), 0, 32)], False, bits=1)
        assert opt.optimize(expr) is None

        # both sides non-constant: nothing to fold
        sub = BinaryOp(
            manager.next_atom(), "Sub", [x, ailment.Expr.Register(manager.next_atom(), 8, 32)], False, bits=32
        )
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [sub, Const(manager.next_atom(), 0, 32)], False, bits=1)
        assert opt.optimize(expr) is None

    def test_cmp_sub_const_chain_canonicalization(self):
        # Behavior-level regression: a strength-reduced sub/dec cascade
        # ((x - 50) - 1) - 1 == 0  must canonicalize to the absolute  x == 52
        # via the full expression peephole pipeline (running to a fixpoint).
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opts = [cls(proj, proj.kb, manager) for cls in EXPR_OPTS]

        x = ailment.Expr.Register(manager.next_atom(), 0, 32)
        chain = BinaryOp(manager.next_atom(), "Sub", [x, Const(manager.next_atom(), 50, 32)], False, bits=32)
        chain = BinaryOp(manager.next_atom(), "Sub", [chain, Const(manager.next_atom(), 1, 32)], False, bits=32)
        chain = BinaryOp(manager.next_atom(), "Sub", [chain, Const(manager.next_atom(), 1, 32)], False, bits=32)
        expr = BinaryOp(manager.next_atom(), "CmpEQ", [chain, Const(manager.next_atom(), 0, 32)], False, bits=1)

        out = peephole_optimize_expr(expr, opts)
        assert isinstance(out, BinaryOp) and out.op == "CmpEQ"
        assert out.operands[0] == x, f"expected bare register on lhs, got {out.operands[0]}"
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 52, f"expected x == 52, got {out}"

    def test_optimized_division_simplifier_keeps_width(self):
        # gcc's `x / k` / `x % k` magic-multiply quotients; the rewritten 64-bit Div must keep the 32-bit width
        for magic, shift, divisor in [(0xCCCCCCCD, 34, 5), (0xAAAAAAAB, 33, 3), (0xD1B71759, 45, 10000)]:
            with self.subTest(divisor=divisor):
                mgr = Manager(arch=archinfo.arch_from_id("AMD64"))
                x = Register(mgr.next_atom(), 16, 64)
                mul = BinaryOp(mgr.next_atom(), "Mul", [Const(mgr.next_atom(), magic, 64), x], False)
                shr = BinaryOp(mgr.next_atom(), "Shr", [mul, Const(mgr.next_atom(), shift, 8)], False)
                expr = Convert(mgr.next_atom(), 64, 32, False, shr)
                r = OptimizedDivisionSimplifier(None, None, mgr).optimize(expr)
                assert isinstance(r, Convert) and r.bits == expr.bits == 32
                assert isinstance(r.operand, BinaryOp) and r.operand.op == "Div"
                divisor_operand = r.operand.operands[1]
                assert isinstance(divisor_operand, Const) and divisor_operand.value == divisor


if __name__ == "__main__":
    unittest.main()
