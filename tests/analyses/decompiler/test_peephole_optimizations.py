#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr import ailment
from angr.ailment.expression import BinaryOp, Call, Const, Convert, Extract, Insert, Register
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import (
    EXPR_OPTS,
    Bswap,
    CmpMaskedShift,
    CmpSubConst,
    ConstantDereferences,
    EagerEvaluation,
    OptimizedDivisionSimplifier,
    RemoveRedundantShifts,
    SimplifyBitwiseInserts,
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

    def test_eager_eval_mul_div_cancellation_requires_integers(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = EagerEvaluation(proj, proj.kb, manager)
        x = Register(manager.next_atom(), 0, 32)

        def mul_div(multiplier, divisor, *, mul_floating_point=False, div_floating_point=False):
            mul = BinaryOp(
                manager.next_atom(),
                "Mul",
                [x, Const(manager.next_atom(), multiplier, 32)],
                False,
                bits=32,
                floating_point=mul_floating_point,
            )
            return BinaryOp(
                manager.next_atom(),
                "Div",
                [mul, Const(manager.next_atom(), divisor, 32)],
                False,
                bits=32,
                floating_point=div_floating_point,
            )

        # (x * 6) / 8 -> (x * 3) / 4
        out = opt.optimize(mul_div(6, 8))
        assert isinstance(out, BinaryOp) and out.op == "Div"
        assert isinstance(out.operands[0], BinaryOp) and out.operands[0].op == "Mul"
        assert out.operands[0].operands[1].value == 3
        assert out.operands[1].value == 4

        # AIL constants may contain floats. Integer cancellation does not apply to them.
        for multiplier, divisor in ((6.0, 8), (6, 8.0), (6.0, 8.0)):
            with self.subTest(multiplier=multiplier, divisor=divisor):
                assert opt.optimize(mul_div(multiplier, divisor)) is None

        # Integer-valued constants do not make floating-point Mul or Div cancellable by an integer GCD.
        for mul_floating_point, div_floating_point in ((True, False), (False, True), (True, True)):
            with self.subTest(
                mul_floating_point=mul_floating_point,
                div_floating_point=div_floating_point,
            ):
                assert (
                    opt.optimize(
                        mul_div(
                            6,
                            8,
                            mul_floating_point=mul_floating_point,
                            div_floating_point=div_floating_point,
                        )
                    )
                    is None
                )

    def test_eager_eval_skips_floating_point_binary_operations(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = EagerEvaluation(proj, proj.kb, manager)
        x = Register(manager.next_atom(), 0, 32)

        for op, operands, bits in (
            ("Mul", (x, Const(manager.next_atom(), 1, 32)), 32),
            ("Add", (x, Const(manager.next_atom(), 0, 32)), 32),
            ("Add", (x, Const(manager.next_atom(), -1, 32)), 32),
            ("CmpEQ", (x, x), 1),
        ):
            with self.subTest(op=op, operands=operands):
                expr = BinaryOp(
                    manager.next_atom(),
                    op,
                    operands,
                    False,
                    bits=bits,
                    floating_point=True,
                )
                assert opt.optimize(expr) is None

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

    def test_remove_redundant_shifts_preserves_sign_extension(self):
        # (x << N) Sar N is a sign-extension of the low (bits - N) bits and must NOT be turned into a
        # zero-extending bitmask. Regression test for the simplifier dropping the sign bit, decompiling
        # `(int)(x << 20) >> 20` (sign-extend the low 12 bits) into the wrong `x & 0xfff` (zero-extend).
        mgr = Manager(arch=archinfo.arch_from_id("AMD64"))

        # Arithmetic shift, standard resulting width (32 - 16 = 16): sign-extend via a *signed* outer Convert.
        x = Register(mgr.next_atom(), 16, 32)
        shl = BinaryOp(mgr.next_atom(), "Shl", [x, Const(mgr.next_atom(), 16, 8)], False, bits=32)
        sar = BinaryOp(mgr.next_atom(), "Sar", [shl, Const(mgr.next_atom(), 16, 8)], True, bits=32)
        r = RemoveRedundantShifts(None, None, mgr).optimize(sar)
        assert isinstance(r, Convert)
        assert r.from_bits == 16 and r.to_bits == 32
        assert r.is_signed is True  # the outer conversion MUST sign-extend (not zero-extend)
        assert isinstance(r.operand, Convert) and r.operand.from_bits == 32 and r.operand.to_bits == 16

        # Arithmetic shift, non-standard resulting width (32 - 20 = 12): leave the Sar/Shl pair intact rather
        # than emit a zero-extend mask that would silently drop the sign bit (12 bits has no clean C type).
        x = Register(mgr.next_atom(), 16, 32)
        shl = BinaryOp(mgr.next_atom(), "Shl", [x, Const(mgr.next_atom(), 20, 8)], False, bits=32)
        sar = BinaryOp(mgr.next_atom(), "Sar", [shl, Const(mgr.next_atom(), 20, 8)], True, bits=32)
        r = RemoveRedundantShifts(None, None, mgr).optimize(sar)
        assert r is None

        # Logical shift (Shr): the low-bit *zero*-extension is correct for any width -> unsigned outer Convert.
        x = Register(mgr.next_atom(), 16, 32)
        shl = BinaryOp(mgr.next_atom(), "Shl", [x, Const(mgr.next_atom(), 20, 8)], False, bits=32)
        shr = BinaryOp(mgr.next_atom(), "Shr", [shl, Const(mgr.next_atom(), 20, 8)], False, bits=32)
        r = RemoveRedundantShifts(None, None, mgr).optimize(shr)
        assert isinstance(r, Convert)
        assert r.from_bits == 12 and r.to_bits == 32
        assert r.is_signed is False  # zero-extend

    def test_bswap32_intrinsic_name(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = Bswap(proj, proj.kb, manager)

        # (Conv(64->32, x) << 0x18) |
        #   ((Conv(64->32, x) << 8) & 0xff0000) |
        #   ((Conv(64->32, x) >> 8) & 0xff00) |
        #   ((Conv(64->32, x) >> 0x18) & 0xff)
        # => __builtin_bswap32(Conv(64->32, x))
        conv = Convert(manager.next_atom(), 64, 32, False, Register(manager.next_atom(), 16, 64))
        p0 = BinaryOp(manager.next_atom(), "Shl", [conv, Const(manager.next_atom(), 0x18, 8)], False, bits=32)
        p1 = BinaryOp(
            manager.next_atom(),
            "And",
            [
                BinaryOp(manager.next_atom(), "Shl", [conv, Const(manager.next_atom(), 8, 8)], False, bits=32),
                Const(manager.next_atom(), 0xFF0000, 32),
            ],
            False,
            bits=32,
        )
        p2 = BinaryOp(
            manager.next_atom(),
            "And",
            [
                BinaryOp(manager.next_atom(), "Shr", [conv, Const(manager.next_atom(), 8, 8)], False, bits=32),
                Const(manager.next_atom(), 0xFF00, 32),
            ],
            False,
            bits=32,
        )
        p3 = BinaryOp(
            manager.next_atom(),
            "And",
            [
                BinaryOp(manager.next_atom(), "Shr", [conv, Const(manager.next_atom(), 0x18, 8)], False, bits=32),
                Const(manager.next_atom(), 0xFF, 32),
            ],
            False,
            bits=32,
        )
        expr = BinaryOp(
            manager.next_atom(),
            "Or",
            [
                p0,
                BinaryOp(
                    manager.next_atom(),
                    "Or",
                    [p1, BinaryOp(manager.next_atom(), "Or", [p2, p3], False, bits=32)],
                    False,
                    bits=32,
                ),
            ],
            False,
            bits=32,
        )

        out = opt.optimize(expr)
        assert isinstance(out, Call)
        assert out.target == "__builtin_bswap32"
        assert len(out.args) == 1 and out.args[0].likes(conv)
        assert out.bits == 32

    def test_bswap16_intrinsic_name(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = Bswap(proj, proj.kb, manager)

        # ((((Conv(16->32, a) << 8) & 0xff00ff00) | ((Conv(16->32, a) >> 8) & 0xff00ff)) & 0xffff)
        # => __builtin_bswap16(a)
        reg = Register(manager.next_atom(), 16, 16)
        shl = BinaryOp(
            manager.next_atom(),
            "Shl",
            [Convert(manager.next_atom(), 16, 32, False, reg), Const(manager.next_atom(), 8, 8)],
            False,
            bits=32,
        )
        shr = BinaryOp(
            manager.next_atom(),
            "Shr",
            [Convert(manager.next_atom(), 16, 32, False, reg), Const(manager.next_atom(), 8, 8)],
            False,
            bits=32,
        )
        inner = BinaryOp(
            manager.next_atom(),
            "Or",
            [
                BinaryOp(manager.next_atom(), "And", [shl, Const(manager.next_atom(), 0xFF00FF00, 32)], False, bits=32),
                BinaryOp(manager.next_atom(), "And", [shr, Const(manager.next_atom(), 0x00FF00FF, 32)], False, bits=32),
            ],
            False,
            bits=32,
        )
        expr = BinaryOp(manager.next_atom(), "And", [inner, Const(manager.next_atom(), 0xFFFF, 32)], False, bits=32)

        out = opt.optimize(expr)
        assert isinstance(out, Call)
        assert out.target == "__builtin_bswap16"
        assert len(out.args) == 1 and out.args[0].likes(reg)

    def test_bitwise_inserts(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = SimplifyBitwiseInserts(proj, proj.kb, manager)

        # Insert(a, 0<64>, (Extract(8, a, 0<8>) Or 44570<16>)) => a Or 44570<16>
        expr = Insert(
            manager.next_atom(),
            Register(manager.next_atom(), 0, 64),
            Const(manager.next_atom(), 0, 64),
            BinaryOp(
                manager.next_atom(),
                "Or",
                [
                    Extract(
                        manager.next_atom(),
                        8,
                        Register(manager.next_atom(), 0, 64),
                        Const(manager.next_atom(), 0, 8),
                        "Iend_LE",
                    ),
                    Const(manager.next_atom(), 44570, 16),
                ],
                False,
            ),
            "Iend_LE",
        )
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "Or"
        assert isinstance(out.operands[0], Register) and out.operands[0].bits == 64
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 44570 and out.operands[1].bits == 64

        # Insert(Conv(8->64, a), 0<64>, (Conv(8->16, a) Or 44570<16>))
        #   => Conv(8->64, a) Or 44570<16>
        expr = Insert(
            manager.next_atom(),
            Convert(manager.next_atom(), 8, 64, False, Register(manager.next_atom(), 0, 8)),
            Const(manager.next_atom(), 0, 64),
            BinaryOp(
                manager.next_atom(),
                "Or",
                [
                    Convert(manager.next_atom(), 8, 16, False, Register(manager.next_atom(), 0, 8)),
                    Const(manager.next_atom(), 44570, 16),
                ],
                False,
            ),
            "Iend_LE",
        )
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "Or"
        assert isinstance(out.operands[0], Convert) and out.operands[0].operand.likes(
            Register(manager.next_atom(), 0, 8)
        )
        assert isinstance(out.operands[1], Const) and out.operands[1].value == 44570 and out.operands[1].bits == 64


if __name__ == "__main__":
    unittest.main()
