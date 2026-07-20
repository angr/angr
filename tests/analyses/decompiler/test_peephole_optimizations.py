#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr import ailment
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Extract,
    Insert,
    Register,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.analyses.decompiler.optimization_passes.peephole_simplifier import PostStructuringPeepholeOptimizationPass
from angr.analyses.decompiler.peephole_optimizations import (
    EXPR_OPTS,
    CmpMaskedShift,
    CmpSubConst,
    ConstantDereferences,
    EagerEvaluation,
    LowerInsert,
    OptimizedDivisionSimplifier,
    RemoveConstInsert,
    SimplifyBitwiseInserts,
)
from angr.analyses.decompiler.structurer_nodes import LoopNode, SequenceNode
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

    @staticmethod
    def _insert(manager, base, offset, value):
        return Insert(
            manager.next_atom(),
            base,
            Const(manager.next_atom(), offset, 64),
            value,
            "Iend_LE",
        )

    def test_lower_insert_is_not_in_the_regular_rotation(self):
        # LowerInsert pre-empts the prettier Insert rewrites, so it must only ever run as a final lowering round
        assert LowerInsert not in EXPR_OPTS

    def test_lower_insert_nonconst_base_offset0(self):
        # the `sete %al` shape: Insert(a, 0<64>, v<8>) => (a And 0xffffffffffffff00) Or Conv(8->64, v)
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = LowerInsert(proj, proj.kb, manager)

        expr = self._insert(manager, Register(manager.next_atom(), 0, 64), 0, Register(manager.next_atom(), 32, 8))
        out = opt.optimize(expr)

        assert isinstance(out, BinaryOp) and out.op == "Or" and out.bits == 64
        masked_base, value = out.operands
        assert isinstance(masked_base, BinaryOp) and masked_base.op == "And"
        assert masked_base.operands[0].likes(Register(manager.next_atom(), 0, 64))
        assert isinstance(masked_base.operands[1], Const) and masked_base.operands[1].value == 0xFFFFFFFFFFFFFF00
        # no shift for offset 0, and the value is zero-extended rather than sign-extended
        assert isinstance(value, Convert) and value.to_bits == 64 and value.is_signed is False
        assert value.operand.likes(Register(manager.next_atom(), 32, 8))

    def test_lower_insert_nonconst_base_nonzero_offset(self):
        # the `and $0xef,%ah` shape: Insert(a, 1<64>, v<8>) => (a And 0xffffffffffff00ff) Or (Conv(8->64, v) Shl 8)
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = LowerInsert(proj, proj.kb, manager)

        expr = self._insert(manager, Register(manager.next_atom(), 0, 64), 1, Register(manager.next_atom(), 32, 8))
        out = opt.optimize(expr)

        assert isinstance(out, BinaryOp) and out.op == "Or" and out.bits == 64
        masked_base, shifted = out.operands
        assert isinstance(masked_base, BinaryOp) and masked_base.op == "And"
        # the mask must punch a hole at byte 1 only - the bytes above it stay live
        assert isinstance(masked_base.operands[1], Const) and masked_base.operands[1].value == 0xFFFFFFFFFFFF00FF
        assert isinstance(shifted, BinaryOp) and shifted.op == "Shl"
        assert isinstance(shifted.operands[1], Const) and shifted.operands[1].value == 8
        assert isinstance(shifted.operands[0], Convert) and shifted.operands[0].to_bits == 64

    def test_lower_insert_const_base_is_folded(self):
        # a constant base is folded, exactly like RemoveConstInsert already does
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()

        base = Const(manager.next_atom(), 0xDEADBEEFDEADBEEF, 64)
        value = Register(manager.next_atom(), 32, 8)

        out = LowerInsert(proj, proj.kb, manager).optimize(self._insert(manager, base, 0, value))
        assert isinstance(out, BinaryOp) and out.op == "Or"
        masked_base, _ = out.operands
        assert isinstance(masked_base, Const) and masked_base.value == 0xDEADBEEFDEADBE00

        # RemoveConstInsert keeps handling this shape on its own, unchanged
        out = RemoveConstInsert(proj, proj.kb, manager).optimize(self._insert(manager, base, 0, value))
        assert isinstance(out, BinaryOp) and out.op == "Or"
        assert any(isinstance(o, Const) and o.value == 0xDEADBEEFDEADBE00 for o in out.operands)

    def test_lower_insert_leaves_stack_variables_alone(self):
        # partial stores into stack variables are rendered as *((char *)&v + offset) = value by the C backend, which is
        # much more readable than mask-and-or arithmetic
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = LowerInsert(proj, proj.kb, manager)

        stack_var = VirtualVariable(manager.next_atom(), 1, 64, VirtualVariableCategory.STACK, oident=-0x10)
        expr = self._insert(manager, stack_var, 1, Register(manager.next_atom(), 32, 8))
        assert opt.optimize(expr) is None

        # ... but a register variable of the same shape is lowered
        reg_var = VirtualVariable(manager.next_atom(), 2, 64, VirtualVariableCategory.REGISTER, oident=0)
        expr = self._insert(manager, reg_var, 1, Register(manager.next_atom(), 32, 8))
        assert isinstance(opt.optimize(expr), BinaryOp)

    def test_lower_insert_bails_on_narrowed_base(self):
        # when the base is a widening Convert and the insert reaches beyond the converted operand's width, the
        # "preserved" bits are extension padding, not data - a telltale of an over-narrowed sub-register write
        # upstream. Lowering would bake that loss into plausible-looking arithmetic, so the Insert must stay visible.
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = LowerInsert(proj, proj.kb, manager)

        # Insert(Conv(8->64, a), 1<64>, v<8>): the insert targets byte 1, entirely above the 8 carried bits
        base = Convert(manager.next_atom(), 8, 64, False, Register(manager.next_atom(), 32, 8))
        expr = self._insert(manager, base, 1, Register(manager.next_atom(), 40, 8))
        assert opt.optimize(expr) is None

        # Insert(Conv(8->64, a), 0<64>, v<16>): the insert straddles the boundary of the carried bits
        base = Convert(manager.next_atom(), 8, 64, False, Register(manager.next_atom(), 32, 8))
        expr = self._insert(manager, base, 0, Register(manager.next_atom(), 40, 16))
        assert opt.optimize(expr) is None

        # Insert(Conv(32->64, a), 0<64>, v<16>): the insert lands entirely within the 32 carried bits - lowered
        base = Convert(manager.next_atom(), 32, 64, False, Register(manager.next_atom(), 32, 32))
        expr = self._insert(manager, base, 0, Register(manager.next_atom(), 40, 16))
        assert isinstance(opt.optimize(expr), BinaryOp)

    def test_lower_insert_bails_on_wide_and_malformed_inserts(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = LowerInsert(proj, proj.kb, manager)

        # wider than a machine word: a bulk memory operation, not a sub-register write. lowering it would only produce
        # arithmetic on integer types that do not exist in C.
        expr = self._insert(manager, Register(manager.next_atom(), 0, 3072), 80, Const(manager.next_atom(), 0, 8))
        assert opt.optimize(expr) is None

        # the value does not fit into the base at the given offset
        expr = self._insert(manager, Register(manager.next_atom(), 0, 64), 7, Register(manager.next_atom(), 32, 16))
        assert opt.optimize(expr) is None

        # a non-constant offset carries no usable shift amount
        expr = Insert(
            manager.next_atom(),
            Register(manager.next_atom(), 0, 64),
            Register(manager.next_atom(), 40, 64),
            Register(manager.next_atom(), 32, 8),
            "Iend_LE",
        )
        assert opt.optimize(expr) is None

    def test_lower_insert_tags_every_generated_subexpression(self):
        # the generated nodes must all carry the original ins_addr, otherwise the codegen's expression-to-address map
        # has no entry for them and the decompiler UI cannot map the arithmetic back to an instruction
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()
        opt = LowerInsert(proj, proj.kb, manager)

        expr = Insert(
            manager.next_atom(),
            Register(manager.next_atom(), 0, 64),
            Const(manager.next_atom(), 1, 64),
            Register(manager.next_atom(), 32, 8),
            "Iend_LE",
            ins_addr=0x400123,
        )
        out = opt.optimize(expr)

        assert out.tags.get("ins_addr") == 0x400123
        masked_base, shifted = out.operands
        # (base And mask)
        assert masked_base.tags.get("ins_addr") == 0x400123
        assert masked_base.operands[1].tags.get("ins_addr") == 0x400123
        # (Conv(8->64, value) Shl 8)
        assert shifted.tags.get("ins_addr") == 0x400123
        assert shifted.operands[0].tags.get("ins_addr") == 0x400123
        assert shifted.operands[1].tags.get("ins_addr") == 0x400123

    def test_lower_insert_width_cutoff_is_c_representable_not_arch_word(self):
        # a 64-bit Insert is `long long` arithmetic - perfectly representable in C - so it must be lowered even when
        # the target's machine word is narrower. Gating on arch.bits left every 32-bit target emitting _INSERT.
        proj = angr.load_shellcode(b"\x90", "X86")
        assert proj.arch.bits == 32
        manager = Manager()
        opt = LowerInsert(proj, proj.kb, manager)

        expr = self._insert(manager, Register(manager.next_atom(), 0, 64), 0, Register(manager.next_atom(), 32, 8))
        assert isinstance(opt.optimize(expr), BinaryOp)

        # ... but anything wider than a C integer type is still left alone
        expr = self._insert(manager, Register(manager.next_atom(), 0, 128), 0, Register(manager.next_atom(), 32, 8))
        assert opt.optimize(expr) is None

    def test_lower_residual_inserts_honors_a_replaced_root_node(self):
        # SequenceWalker cannot rewrite a LoopNode in place - it returns a fresh one. When the root of the sequence is
        # itself a LoopNode, discarding walk()'s return value silently drops the lowering for its initializer.
        proj = angr.load_shellcode(b"\x90", "AMD64")
        manager = Manager()

        # for (v = _INSERT(rax, 0, al); ...) - the Insert lives in the loop initializer, i.e. a bare statement
        insert = self._insert(manager, Register(manager.next_atom(), 0, 64), 0, Register(manager.next_atom(), 32, 8))
        initializer = ailment.Stmt.Assignment(
            manager.next_atom(), VirtualVariable(manager.next_atom(), 3, 64, VirtualVariableCategory.REGISTER), insert
        )
        loop = LoopNode("while", None, SequenceNode(0x400000, nodes=[]), addr=0x400000, initializer=initializer)

        pass_ = PostStructuringPeepholeOptimizationPass.__new__(PostStructuringPeepholeOptimizationPass)
        pass_.seq = loop
        pass_._lowering_opts = [LowerInsert(proj, proj.kb, manager)]
        pass_._lower_residual_inserts()

        assert isinstance(pass_.seq, LoopNode)
        assert not isinstance(pass_.seq.initializer.src, Insert), "the Insert survived in the loop initializer"
        assert isinstance(pass_.seq.initializer.src, BinaryOp) and pass_.seq.initializer.src.op == "Or"


if __name__ == "__main__":
    unittest.main()
