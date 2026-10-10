"""Unit tests for FP-related peephole optimizations.

Tests peephole logic directly by constructing AIL expressions,
without running the full decompiler pipeline.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import struct
import time
import unittest
from typing import TYPE_CHECKING

import angr
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Extract,
    Insert,
    Tmp,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)

if TYPE_CHECKING:
    from angr.analyses.decompiler.peephole_optimizations.remove_redundant_conversions import (
        RemoveRedundantConversions,
    )


def _proj():
    return angr.load_shellcode(b"\xc3", "amd64")


def _make_peephole(cls):
    from angr.ailment.manager import Manager

    proj = _proj()
    mgr = Manager()
    return cls(proj, proj.kb, ail_manager=mgr, func_addr=0x400000)


# ======================================================================
# evaluate_const_conversions: FP constant folding
# ======================================================================


class TestEvaluateConstConversions(unittest.TestCase):
    """Test FP constant evaluation in Convert expressions."""

    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.evaluate_const_conversions import EvaluateConstConversions

        opt = _make_peephole(EvaluateConstConversions)
        return opt.optimize(expr)

    def test_float32_to_float64(self):
        """Conv(32F->64F, 3.14f) should produce the double bit pattern."""
        # 3.14f as 32-bit IEEE 754
        (bits32,) = struct.unpack("<I", struct.pack("<f", 3.14))
        inner = Const(1, bits32, 32)
        expr = Convert(2, 32, 64, False, inner, from_type=Convert.TYPE_FP, to_type=Convert.TYPE_FP)
        result = self._opt(expr)
        assert result is not None
        assert result.bits == 64
        # Verify the value is correct
        (f64,) = struct.unpack("<d", struct.pack("<Q", result.value))
        assert abs(f64 - 3.14) < 0.01

    def test_float64_to_float32(self):
        """Conv(64F->32F, 2.718) should produce the float bit pattern."""
        (bits64,) = struct.unpack("<Q", struct.pack("<d", 2.718))
        inner = Const(1, bits64, 64)
        expr = Convert(2, 64, 32, False, inner, from_type=Convert.TYPE_FP, to_type=Convert.TYPE_FP)
        result = self._opt(expr)
        assert result is not None
        assert result.bits == 32
        (f32,) = struct.unpack("<f", struct.pack("<I", result.value))
        assert abs(f32 - 2.718) < 0.01

    def test_int_to_float64(self):
        """Conv(32I->64F, 42) should produce the double bit pattern for 42.0."""
        inner = Const(1, 42, 32)
        expr = Convert(2, 32, 64, True, inner, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP)
        result = self._opt(expr)
        assert result is not None
        assert result.bits == 64
        (f64,) = struct.unpack("<d", struct.pack("<Q", result.value))
        assert f64 == 42.0

    def test_signed_int_to_float64(self):
        """Conv(32I->64F, -1 as unsigned) should produce -1.0."""
        inner = Const(1, 0xFFFFFFFF, 32)  # -1 as unsigned 32-bit
        expr = Convert(2, 32, 64, True, inner, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP)
        result = self._opt(expr)
        assert result is not None
        (f64,) = struct.unpack("<d", struct.pack("<Q", result.value))
        assert f64 == -1.0

    def test_non_fp_convert_returns_none(self):
        """Non-FP Convert should not be handled by FP evaluator."""
        inner = Const(1, 42, 32)
        expr = Convert(2, 32, 64, False, inner, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        # This goes through the integer path, not _try_evaluate_fp_convert
        result = self._opt(expr)
        # Integer widening: 42 stays 42
        assert result is not None
        assert result.value == 42


# ======================================================================
# remove_redundant_conversions: Conv round-trip and FP retyping
# ======================================================================


def _RRC():
    from angr.analyses.decompiler.peephole_optimizations.remove_redundant_conversions import (
        RemoveRedundantConversions,
    )

    return RemoveRedundantConversions


class TestRemoveRedundantConversions(unittest.TestCase):
    """Test redundant Conv elimination for FP patterns."""

    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.remove_redundant_conversions import (
            RemoveRedundantConversions,
        )

        opt = _make_peephole(RemoveRedundantConversions)
        return opt.optimize(expr)

    def test_fp_widened_compare_narrows_to_a_float_constant(self):
        """Conv(32F->64F, x) == 0.0 compares x against 0.0f, as a float comparison; 0.1 is not a float."""
        from angr.ailment.expression import VirtualVariable, VirtualVariableCategory

        x = VirtualVariable(1, 10, 32, category=VirtualVariableCategory.REGISTER, oident=224)
        widened = Convert(2, 32, 64, False, x, from_type=Convert.TYPE_FP, to_type=Convert.TYPE_FP)
        (zero_bits,) = struct.unpack("<Q", struct.pack("<d", 0.0))
        result = self._opt(BinaryOp(3, "CmpEQ", [widened, Const(4, zero_bits, 64)], False))
        assert isinstance(result, BinaryOp) and result.op == "CmpEQ" and result.floating_point
        assert result.operands[0].likes(x) and result.operands[1].bits == 32 and result.operands[1].value == 0
        (tenth_bits,) = struct.unpack("<Q", struct.pack("<d", 0.1))
        assert self._opt(BinaryOp(5, "CmpEQ", [widened, Const(6, tenth_bits, 64)], False)) is None

    def test_fp_narrowing_of_int_widening(self):
        """Conv(64F->32F, Conv(32I->64I, x)) should eliminate both Convs."""
        x = Const(1, 42, 32)
        inner = Convert(2, 32, 64, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        outer = Convert(3, 64, 32, False, inner, from_type=Convert.TYPE_FP, to_type=Convert.TYPE_FP)
        result = self._opt(outer)
        assert result == x

    def test_same_type_round_trip(self):
        """Conv(64I->32I, Conv(32I->64I, x)) should eliminate both."""
        x = Const(1, 42, 32)
        inner = Convert(2, 32, 64, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        outer = Convert(3, 64, 32, False, inner, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        result = self._opt(outer)
        assert result == x

    def test_insert_truncation_preserves_extra_def(self):
        vvar = VirtualVariable(1, 10, 32, category=VirtualVariableCategory.STACK, oident=-4)
        reference = UnaryOp(2, "Reference", vvar, bits=32, extra_def=True)
        inserted = Insert(3, reference, Const(4, 0, 64), Tmp(5, 0, 8), "Iend_LE")
        truncation = Convert(6, 32, 8, False, inserted)

        assert self._opt(truncation) is None

    def _float_call(self, idx: int) -> tuple[RemoveRedundantConversions, Call]:
        from angr.analyses.decompiler.variable_map import variable_map_of
        from angr.sim_type import SimTypeFloat, SimTypeFunction

        opt = _make_peephole(_RRC())
        call = Call(idx, Const(None, 0x401000, 64), args=[], bits=32)
        variable_map_of(opt.manager).set_prototype(call, SimTypeFunction([], SimTypeFloat()))
        return opt, call

    def test_float_call_widening_retyped(self):
        """Conv(32I->64I, Call<float>) -> Conv(32F->64F, Call)."""
        opt, call = self._float_call(1)
        conv = Convert(2, 32, 64, False, call, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        result = opt.optimize(conv)
        assert isinstance(result, Convert)
        assert (result.from_type, result.to_type) == (Convert.TYPE_FP, Convert.TYPE_FP)

    def test_float_call_int_narrowing_kept(self):
        """Conv(32I->16I, Call<float>) reads the low 16 bits (cmp ax, ...): no 16-bit float."""
        opt, call = self._float_call(1)
        conv = Convert(2, 32, 16, False, call, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        assert opt.optimize(conv) is None

    def test_unary_conv_round_trip(self):
        """Conv(128->64, Neg(Conv(64->128, x))) should produce Neg(x)."""
        x = Const(1, 42, 64)
        inner_conv = Convert(2, 64, 128, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        neg = UnaryOp(3, "Neg", inner_conv, bits=128)
        outer = Convert(4, 128, 64, False, neg, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        result = self._opt(outer)
        assert result is not None
        assert isinstance(result, UnaryOp)
        assert result.operand == x
        assert result.bits == 64


# ======================================================================
# FP sign-bit XOR to negation is now handled by the FpNegation optimization
# pass (post variable-recovery, type-aware) rather than a peephole, so its
# behavior is covered by the end-to-end negate_* cases in test_fp.py.
# ======================================================================


# ======================================================================
# sse_scalar_lowering: Extract(BinOp/UnaryOp) -> scalar
# ======================================================================


class TestSSEScalarLowering(unittest.TestCase):
    """Test SSE scalar-in-vector lowering."""

    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.sse_scalar_lowering import SSEScalarLowering

        opt = _make_peephole(SSEScalarLowering)
        return opt.optimize(expr)

    def test_extract_mulv(self):
        """Extract(MulV(Conv(64->128,a), Conv(64->128,b)), 64@0) -> Mul(a, b)."""
        a = Const(1, 42, 64)
        b = Const(2, 43, 64)
        conv_a = Convert(3, 64, 128, False, a, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        conv_b = Convert(4, 64, 128, False, b, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        mulv = BinaryOp(5, "MulV", [conv_a, conv_b], False, floating_point=True, bits=128)
        zero = Const(6, 0, 64)
        extract = Extract(7, 64, mulv, zero, "Iend_LE")
        result = self._opt(extract)
        assert result is not None
        assert isinstance(result, BinaryOp)
        assert result.op == "Mul"
        assert result.floating_point is True
        assert result.bits == 64

    def test_extract_neg_conv(self):
        """Extract(Neg(Conv(64->128, x)), 64@0) -> Neg(x, fp=True)."""
        x = Const(1, 42, 64)
        conv = Convert(2, 64, 128, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        neg = UnaryOp(3, "Neg", conv, bits=128)
        zero = Const(4, 0, 64)
        extract = Extract(5, 64, neg, zero, "Iend_LE")
        result = self._opt(extract)
        assert result is not None
        assert isinstance(result, UnaryOp)
        assert result.op == "Neg"
        assert result.operand == x
        assert result.bits == 64
        assert result.floating_point is True

    def test_extract_lane_wise_convert(self):
        """Extract(ConvV(I32StoF32x4, Conv(32->128, x)), 32@0) -> Convert(I32->F32, x)."""
        x = Const(1, 42, 32)
        conv = Convert(2, 32, 128, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        convv = Convert(3, 128, 128, True, conv, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP, vector_count=4)
        extract = Extract(4, 32, convv, Const(5, 0, 64), "Iend_LE")
        result = self._opt(extract)
        assert isinstance(result, Convert)
        assert result.vector_count is None
        assert (result.from_bits, result.to_bits) == (32, 32)
        assert (result.from_type, result.to_type) == (Convert.TYPE_INT, Convert.TYPE_FP)
        assert result.is_signed is True
        assert result.operand == x

    def test_extract_lane_wise_convert_wrong_width(self):
        """Extract(ConvV(F32toF64x2, a), 32@0) reads half a lane: no match."""
        a = Const(1, 42, 128)
        convv = Convert(2, 64, 128, False, a, from_type=Convert.TYPE_FP, to_type=Convert.TYPE_FP, vector_count=2)
        extract = Extract(3, 32, convv, Const(4, 0, 64), "Iend_LE")
        assert self._opt(extract) is None

    def test_non_vector_op_returns_none(self):
        """Extract(BinaryOp("Add", ...), 64@0) should not match (no V suffix)."""
        a = Const(1, 42, 128)
        b = Const(2, 43, 128)
        add = BinaryOp(3, "Add", [a, b], False, bits=128)
        zero = Const(4, 0, 64)
        extract = Extract(5, 64, add, zero, "Iend_LE")
        result = self._opt(extract)
        assert result is None


class TestSSEVectorConvertLowering(unittest.TestCase):
    """ConvV(Conv(N->128, x)) -> Conv(M->128, Convert(N->M, x))."""

    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.sse_scalar_lowering import SSEVectorConvertLowering

        return _make_peephole(SSEVectorConvertLowering).optimize(expr)

    def test_widened_scalar(self):
        x = Const(1, 42, 32)
        conv = Convert(2, 32, 128, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        convv = Convert(3, 128, 128, True, conv, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP, vector_count=4)
        result = self._opt(convv)
        assert isinstance(result, Convert)
        assert result.vector_count is None
        assert (result.from_bits, result.to_bits) == (32, 128)
        inner = result.operand
        assert isinstance(inner, Convert)
        assert (inner.from_bits, inner.to_bits) == (32, 32)
        assert (inner.from_type, inner.to_type) == (Convert.TYPE_INT, Convert.TYPE_FP)
        assert inner.operand == x

    def test_sign_extended_scalar_not_lowered(self):
        """Sign extension may put non-zero bits in the upper lanes."""
        x = Const(1, 42, 32)
        conv = Convert(2, 32, 128, True, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        convv = Convert(3, 128, 128, True, conv, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP, vector_count=4)
        assert self._opt(convv) is None

    def test_full_vector_not_lowered(self):
        a = Const(1, 42, 128)
        convv = Convert(2, 128, 128, True, a, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP, vector_count=4)
        assert self._opt(convv) is None


# ======================================================================
# sse_bitwise_select: SSE bitwise select -> ITE
# ======================================================================


class TestSSEBitwiseSelect(unittest.TestCase):
    """Test SSE bitwise select recognition and ITE narrowing."""

    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.sse_bitwise_select import SSEBitwiseSelect

        opt = _make_peephole(SSEBitwiseSelect)
        return opt.optimize(expr)

    def test_select_branch_order(self):
        """(~mask & A) | (B & mask) with mask = CmpLTV(0, x) -> ITE(0 < x, B, A)."""
        x = Const(1, 42, 64)
        zero = Const(2, 0, 64)
        a = Const(3, 10, 64)
        b = Const(4, 20, 64)
        mask = BinaryOp(5, "CmpLTV", [zero, x], False, floating_point=True, bits=64)
        not_mask = UnaryOp(6, "BitwiseNeg", mask, bits=64)
        arm_a = BinaryOp(7, "And", [not_mask, a], False, bits=64)
        arm_b = BinaryOp(8, "And", [b, mask], False, bits=64)
        expr = BinaryOp(9, "Or", [arm_a, arm_b], False, bits=64)
        result = self._opt(expr)
        assert isinstance(result, ITE)
        assert isinstance(result.cond, BinaryOp) and result.cond.op == "CmpLT"
        assert result.iftrue == b
        assert result.iffalse == a

    def test_extract_ite_narrowing_keeps_branch_order(self):
        """Extract(ITE(c, a, b), 8@0) -> ITE(c, Extract(a), Extract(b))."""
        a = Const(1, 10, 32)
        b = Const(2, 20, 32)
        cond = BinaryOp(3, "CmpEQ", [Const(4, 1, 32), Const(5, 0, 32)], False, bits=1)
        ite = ITE(6, cond, a, b, bits=32)
        extract = Extract(7, 8, ite, Const(8, 0, 32), "Iend_LE")
        result = self._opt(extract)
        assert isinstance(result, ITE)
        assert result.bits == 8
        assert isinstance(result.iftrue, Extract) and result.iftrue.base == a
        assert isinstance(result.iffalse, Extract) and result.iffalse.base == b

    def test_extract_ite_narrowing_keeps_scalar_condition(self):
        """Extract(ITE(a != b, x, y), 8@0) must not narrow the doubles the condition compares."""
        from angr.ailment.expression import VirtualVariable, VirtualVariableCategory

        a = VirtualVariable(1, 10, 64, category=VirtualVariableCategory.REGISTER, oident=72)
        b = VirtualVariable(2, 11, 64, category=VirtualVariableCategory.REGISTER, oident=88)
        ne = BinaryOp(3, "CmpNE", [a, b], False, floating_point=True)
        ite = ITE(4, ne, Const(5, 0, 32), Const(6, 1, 32), bits=32)
        result = self._opt(Extract(7, 8, ite, Const(8, 0, 32), "Iend_LE"))
        assert isinstance(result, ITE) and result.bits == 8
        assert isinstance(result.cond, BinaryOp) and result.cond.likes(ne)
        assert all(op.bits == 64 for op in result.cond.operands)


# ======================================================================
# float Const guards: integer peepholes must leave float constants alone
# ======================================================================


class TestFloatConstGuards(unittest.TestCase):
    """Const.value may be a Python float; peepholes doing integer arithmetic on it must return None, not raise."""

    def test_eager_eval(self):
        from angr.analyses.decompiler.peephole_optimizations.eager_eval import EagerEvaluation

        opt = _make_peephole(EagerEvaluation)
        x = Tmp(1, 0, 64)
        f = Const(2, 2.5, 64)
        assert opt.optimize(BinaryOp(3, "Shl", [f, Const(4, 3, 8)], False, bits=64)) is None
        assert opt.optimize(BinaryOp(3, "Shr", [f, Const(4, 3, 8)], False, bits=64)) is None
        assert opt.optimize(BinaryOp(3, "Shr", [x, Const(4, 1.0, 8)], False, bits=64)) is None
        inner = BinaryOp(5, "Shr", [x, Const(6, 2.0, 8)], False, bits=64)
        assert opt.optimize(BinaryOp(3, "Shr", [inner, Const(4, 3, 8)], False, bits=64)) is None
        inner = BinaryOp(5, "Add", [x, f], False, bits=64)
        assert opt.optimize(BinaryOp(3, "Add", [inner, Const(4, 3, 64)], False, bits=64)) is None
        assert opt.optimize(BinaryOp(3, "Sub", [inner, Const(4, 3, 64)], False, bits=64)) is None
        inner = BinaryOp(5, "Mul", [x, f], False, bits=64)
        assert opt.optimize(BinaryOp(3, "Mul", [inner, Const(4, 3, 64)], False, bits=64)) is None
        assert opt.optimize(BinaryOp(3, "Add", [inner, x], False, bits=64)) is None
        assert opt.optimize(BinaryOp(3, "Sub", [inner, x], False, bits=64)) is None

    def test_bitwise_inserts(self):
        from angr.analyses.decompiler.peephole_optimizations.bitwise_inserts import SimplifyBitwiseInserts

        opt = _make_peephole(SimplifyBitwiseInserts)
        base = Const(1, 7, 64)
        low = Extract(2, 32, base, Const(3, 0, 64), "Iend_LE")
        value = BinaryOp(4, "Or", [low, Const(5, 2.5, 32)], False, bits=32)
        assert opt.optimize(Insert(6, base, Const(7, 0, 64), value, "Iend_LE")) is None

    def test_sse_scalar_lowering(self):
        from angr.analyses.decompiler.peephole_optimizations.sse_scalar_lowering import _strip_lane0

        x = Const(1, 7, 64)
        assert _strip_lane0(BinaryOp(2, "Or", [x, Const(3, 2.5, 64)], False, bits=64), 32) is None

    def test_remove_const_insert(self):
        from angr.analyses.decompiler.peephole_optimizations.remove_const_insert import RemoveConstInsert

        opt = _make_peephole(RemoveConstInsert)
        expr = Insert(1, Const(2, 2.5, 64), Const(3, 0, 64), Const(4, 1, 32), "Iend_LE")
        assert opt.optimize(expr) is None

    def test_remove_redundant_bitmasks(self):
        from angr.analyses.decompiler.peephole_optimizations.remove_redundant_bitmasks import RemoveRedundantBitmasks

        opt = _make_peephole(RemoveRedundantBitmasks)
        masked = BinaryOp(1, "And", [Const(2, 7, 64), Const(3, 2.5, 64)], False, bits=64)
        assert opt.optimize(Insert(4, masked, Const(5, 0, 64), Const(6, 1, 32), "Iend_LE")) is None
        assert opt.optimize(Extract(4, 32, masked, Const(5, 0, 64), "Iend_LE")) is None

    def test_coalesce_adjacent_shrs(self):
        from angr.analyses.decompiler.peephole_optimizations.coalesce_adjacent_shrs import CoalesceAdjacentShiftRights

        opt = _make_peephole(CoalesceAdjacentShiftRights)
        inner = BinaryOp(1, "Shr", [Const(2, 7, 64), Const(3, 2.5, 8)], False, bits=64)
        assert opt.optimize(BinaryOp(4, "Shr", [inner, Const(5, 1, 8)], False, bits=64)) is None

    def test_sar_to_signed_div(self):
        from angr.analyses.decompiler.peephole_optimizations.sar_to_signed_div import SarToSignedDiv

        opt = _make_peephole(SarToSignedDiv)
        x = Const(1, 7, 32)
        assert opt.optimize(BinaryOp(2, "Sar", [x, Const(3, 1.0, 8)], True, bits=32)) is None
        shr = BinaryOp(4, "Shr", [x, Const(5, 31.0, 8)], False, bits=32)
        assert SarToSignedDiv._check_signedness(BinaryOp(6, "CmpEQ", [shr, Const(7, 1, 32)], False, bits=1)) is None
        masked = BinaryOp(8, "And", [BinaryOp(9, "Shr", [x, Const(10, 15.0, 8)], False, bits=32), Const(11, 1, 32)])
        assert SarToSignedDiv._check_signedness(BinaryOp(6, "CmpEQ", [masked, Const(7, 1, 32)], False, bits=1)) is None

    def test_rol_ror(self):
        from angr.ailment.block import Block
        from angr.ailment.statement import Assignment
        from angr.analyses.decompiler.peephole_optimizations.rol_ror import RolRorRewriter

        opt = _make_peephole(RolRorRewriter)
        x = Tmp(1, 0, 32)
        t1, t2, t3 = Tmp(2, 1, 32), Tmp(3, 2, 32), Tmp(4, 3, 32)
        stmts = [
            Assignment(5, t1, BinaryOp(6, "Shr", [x, Const(7, 25.0, 8)], False, bits=32)),
            Assignment(8, t2, BinaryOp(9, "Shl", [x, Const(10, 7, 8)], False, bits=32)),
            Assignment(11, t3, BinaryOp(12, "Or", [t2, t1], False, bits=32)),
        ]
        block = Block(0x400000, 12, statements=[*stmts])
        assert opt.optimize(stmts[2], 2, block) is None


# ======================================================================
# sse_vector_lane_lowering: lane-0 reads of lane-wise vector ops
# ======================================================================


class TestSSEVectorLaneLowering(unittest.TestCase):
    """Lane-0 reads of ShrNV/SubV/CmpEQV/MulV/ConvV collapse to scalar ops."""

    def setUp(self):
        from angr.analyses.decompiler.peephole_optimizations.remove_redundant_ite_comparisons import (
            RemoveRedundantITEComparisons,
        )
        from angr.analyses.decompiler.peephole_optimizations.sse_vector_lane_lowering import SSEVectorLaneLowering

        self.opt = _make_peephole(SSEVectorLaneLowering)
        self.ite_opt = _make_peephole(RemoveRedundantITEComparisons)
        self.x = Tmp(1, 1, 128)
        self.y = Tmp(2, 2, 128)

    @staticmethod
    def _lsb(bits, base):
        return Extract(None, bits, base, Const(None, 0, 64), "Iend_LE")

    def _vec(self, op, a, b, **kw):
        return BinaryOp(None, op, [a, b], kw.pop("signed", False), bits=128, vector_count=2, vector_size=64, **kw)

    def test_psrlq_exponent_extraction(self):
        """Conv(128->16, ShrNV(x, 52)) -> Conv(64->16, lane0(x) >> 52) (psrlq + pextrw)."""
        shr = self._vec("ShrNV", self.x, Const(None, 52, 8))
        r = self.opt.optimize(Convert(None, 128, 16, False, shr))
        assert isinstance(r, Convert) and (r.from_bits, r.to_bits) == (64, 16)
        assert isinstance(r.operand, BinaryOp) and r.operand.op == "Shr" and r.operand.bits == 64
        assert isinstance(r.operand.operands[0], Extract) and r.operand.operands[0].bits == 64
        # a full-lane read needs no wrapper
        r = self.opt.optimize(self._lsb(64, shr))
        assert isinstance(r, BinaryOp) and r.op == "Shr" and r.bits == 64

    def test_psubq_lane0_with_vector_constant(self):
        """Conv(128->64, SubV(c128, Conv(64->128, t))) -> Sub(lane0(c128), t)."""
        t = Tmp(3, 3, 64)
        sub = self._vec("SubV", Const(None, 0x3FF00000000000003FF0000000000000, 128), Convert(None, 64, 128, False, t))
        r = self.opt.optimize(Convert(None, 128, 64, False, sub))
        assert isinstance(r, BinaryOp) and r.op == "Sub" and r.bits == 64 and not r.floating_point
        assert isinstance(r.operands[0], Const) and r.operands[0].value == 0x3FF0000000000000
        assert r.operands[1] == t

    def test_cmpeqsd_mask_to_condition(self):
        """Extract(CmpEQV(0, y), 16@0) -> ITE(0 == lane0(y), 0xffff, 0); the mask test folds to the condition."""
        cmp = self._vec("CmpEQV", Const(None, 0, 128), self.y, floating_point=True)
        r = self.opt.optimize(self._lsb(16, cmp))
        assert isinstance(r, ITE) and r.bits == 16
        assert isinstance(r.cond, BinaryOp) and r.cond.op == "CmpEQ" and r.cond.floating_point
        assert isinstance(r.iftrue, Const) and r.iftrue.value == 0xFFFF
        assert isinstance(r.iffalse, Const) and r.iffalse.value == 0
        # pextrw eax, xmm, 0 ; cmp eax, 0 ; ja  ->  the condition itself
        assert self.ite_opt.optimize(BinaryOp(None, "CmpGT", [r, Const(None, 0, 16)], False, bits=1)) == r.cond
        # ... & 1
        assert self.ite_opt.optimize(BinaryOp(None, "And", [r, Const(None, 1, 16)], False, bits=16)) == r.cond
        # ... & 0xff keeps a (narrower) mask
        masked = self.ite_opt.optimize(BinaryOp(None, "And", [r, Const(None, 0xFF, 16)], False, bits=16))
        assert isinstance(masked, ITE) and isinstance(masked.iftrue, Const) and masked.iftrue.value == 0xFF

    def test_mulpd_lane0_is_scalar_fp_mul(self):
        mul = self._vec("MulV", self.x, self.y, signed=True, floating_point=True)
        r = self.opt.optimize(self._lsb(64, mul))
        assert isinstance(r, BinaryOp) and r.op == "Mul" and r.bits == 64 and r.floating_point

    def test_reads_above_lane0_are_left_alone(self):
        mul = self._vec("MulV", self.x, self.y, signed=True, floating_point=True)
        assert self.opt.optimize(self._lsb(128, mul)) is None
        assert self.opt.optimize(Extract(None, 64, mul, Const(None, 8, 64), "Iend_LE")) is None

    def test_cvtdq2ps_on_movd_lane(self):
        """Extract(ConvV(32->s32Fx4, Conv(32->128, t)), 32@0) -> Conv(32->s32F, t); a 64-bit read zero-extends."""
        t = Tmp(4, 4, 32)
        cv = Convert(
            None,
            128,
            128,
            True,
            Convert(None, 32, 128, False, t),
            from_type=Convert.TYPE_INT,
            to_type=Convert.TYPE_FP,
            vector_count=4,
        )
        r = self.opt.optimize(self._lsb(32, cv))
        assert isinstance(r, Convert) and (r.from_bits, r.to_bits) == (32, 32)
        assert r.from_type == Convert.TYPE_INT and r.to_type == Convert.TYPE_FP and r.operand == t
        r = self.opt.optimize(Convert(None, 128, 64, False, cv))
        assert isinstance(r, Convert) and (r.from_bits, r.to_bits) == (32, 64) and r.to_type == Convert.TYPE_INT
        assert isinstance(r.operand, Convert) and r.operand.to_type == Convert.TYPE_FP


class TestRecombineSplitHalves(unittest.TestCase):
    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.recombine_split_halves import RecombineSplitHalves

        return _make_peephole(RecombineSplitHalves).optimize(expr)

    def _recombine(self, a):
        lo = BinaryOp(None, "And", [a, Const(None, 0xFFFFFFFF, 64)], False, bits=64)
        shr = BinaryOp(None, "Shr", [a, Const(None, 32, 8)], False, bits=64)
        hi = BinaryOp(None, "Mul", [shr, Const(None, 0x100000000, 64)], False, bits=64)
        return BinaryOp(None, "Or", [lo, hi], False, bits=64)

    def test_mask_or_shifted_high_half(self):
        a = Tmp(None, 1, 64)
        r = self._opt(self._recombine(a))
        assert r is not None and r.likes(a)

    def test_call_is_not_folded(self):
        # each half re-issues the call
        assert self._opt(self._recombine(Call(None, "f", args=[], bits=64))) is None


if __name__ == "__main__":
    unittest.main()


# ======================================================================
# X87CmpF / X86CCallRewriter: fnstsw ax; test ah, imm / sahf / cmp ah idioms
# ======================================================================


def _cmpf(a, b):
    return BinaryOp(None, "CmpF", [a, b], False, bits=32, floating_point=True)


def _fsw_ah(cmpf, ftop):
    """(char)(((ftop & 7) * 0x800 | CmpF * 0x100 & 0x4500 & 0x4700) >> 8), as lifted from fnstsw ax."""
    ftop_part = BinaryOp(
        None,
        "Mul",
        [BinaryOp(None, "And", [ftop, Const(None, 7, 16)], False, bits=16), Const(None, 0x800, 16)],
        False,
        bits=16,
    )
    fc3210 = BinaryOp(
        None,
        "And",
        [
            BinaryOp(None, "Mul", [Convert(None, 32, 16, False, cmpf), Const(None, 0x100, 16)], False, bits=16),
            Const(None, 0x4500, 16),
        ],
        False,
        bits=16,
    )
    fsw = BinaryOp(
        None,
        "Or",
        [ftop_part, BinaryOp(None, "And", [fc3210, Const(None, 0x4700, 16)], False, bits=16)],
        False,
        bits=16,
    )
    return Convert(None, 16, 8, False, BinaryOp(None, "Shr", [fsw, Const(None, 8, 8)], False, bits=16))


def _test_ah(cmpf, ftop, mask):
    """Conv(8->32, ah & mask): cc_dep1 of test ah, mask."""
    return Convert(
        None, 8, 32, False, BinaryOp(None, "And", [_fsw_ah(cmpf, ftop), Const(None, mask, 8)], False, bits=8)
    )


def _sahf_eflags(cmpf, ftop, old_eflags):
    """old_eflags & 0x800 | (eax >> 8) & 0xd5 with eax = _INSERT(_INSERT(0, 0, al), 1, ah): cc_dep1 after sahf."""
    al = BinaryOp(
        None,
        "Mul",
        [
            BinaryOp(None, "And", [Convert(None, 16, 8, False, ftop), Const(None, 7, 8)], False, bits=8),
            Const(None, 0, 8),
        ],
        False,
        bits=8,
    )
    eax = Insert(
        None,
        Insert(None, Const(None, 0, 32), Const(None, 0, 32), al, "Iend_LE"),
        Const(None, 1, 32),
        _fsw_ah(cmpf, ftop),
        "Iend_LE",
    )
    return BinaryOp(
        None,
        "Or",
        [
            BinaryOp(None, "And", [old_eflags, Const(None, 0x800, 32)], False, bits=32),
            BinaryOp(
                None,
                "And",
                [BinaryOp(None, "Shr", [eax, Const(None, 8, 8)], False, bits=32), Const(None, 0xD5, 32)],
                False,
                bits=32,
            ),
        ],
        False,
        bits=32,
    )


def _bit(expr, shift):
    """(expr >> shift) & 1"""
    return BinaryOp(
        None,
        "And",
        [BinaryOp(None, "Shr", [expr, Const(None, shift, 8)], False, bits=expr.bits), Const(None, 1, expr.bits)],
        False,
        bits=expr.bits,
    )


def _cmp_const(op, expr, value):
    return BinaryOp(None, op, [expr, Const(None, value, expr.bits)], False, bits=1)


class TestSSEMoveMask(unittest.TestCase):
    """vmovmskpd's per-lane sign-bit Or-tree folds into MovMskPD; a bit-0 read becomes SignBit(lane 0)."""

    def test_vmovmskpd_ymm(self):
        from angr.analyses.decompiler.peephole_optimizations.sse_movemask import SSEMoveMask

        opt = _make_peephole(SSEMoveMask)
        y = Tmp(1, 1, 256)

        def term(i):
            word = Extract(None, 32, y, Const(None, (i + 1) * 8 - 4, 64), "Iend_LE")
            shr = BinaryOp(None, "Shr", [word, Const(None, 31 - i, 8)], False, bits=32)
            return BinaryOp(None, "And", [shr, Const(None, 1 << i, 32)], False, bits=32)

        def or_(a, b):
            return BinaryOp(None, "Or", [a, b], False, bits=32)

        r = opt.optimize(or_(or_(term(0), term(1)), or_(term(2), term(3))))
        assert isinstance(r, UnaryOp) and r.op == "MovMskPD" and r.operand.likes(y)
        # a lane missing or out of place is not a movemask
        assert opt.optimize(or_(or_(term(0), term(1)), or_(term(2), term(2)))) is None
        r = opt.optimize(BinaryOp(None, "And", [r, Const(None, 1, 32)], False, bits=32))
        assert isinstance(r, Convert) and (r.from_bits, r.to_bits) == (1, 32)
        sign = r.operand
        assert isinstance(sign, UnaryOp) and sign.op == "SignBit" and sign.operand.bits == 64


class TestSbbMaskToITE(unittest.TestCase):
    """cmp x, 1; sbb eax, eax; and eax, K; sub eax, D  ->  ITE."""

    def test_sbb_select(self):
        from angr.analyses.decompiler.peephole_optimizations.sbb_mask_to_ite import SbbMaskToITE

        opt = _make_peephole(SbbMaskToITE)
        b = Tmp(1, 1, 1)
        lt = opt.optimize(BinaryOp(None, "CmpLT", [b, Const(None, 1, 1)], False, bits=1))
        assert isinstance(lt, UnaryOp) and lt.op == "Not" and lt.operand.likes(b)
        neg = UnaryOp(None, "Neg", Convert(None, 1, 32, False, lt), bits=32)
        ite = opt.optimize(BinaryOp(None, "And", [neg, Const(None, 2, 32)], False, bits=32))
        assert isinstance(ite, ITE) and isinstance(ite.iftrue, Const) and isinstance(ite.iffalse, Const)
        assert ite.iftrue.value == 2 and ite.iffalse.value == 0
        ite = opt.optimize(BinaryOp(None, "Sub", [ite, Const(None, 1, 32)], False, bits=32))
        assert isinstance(ite, ITE) and isinstance(ite.iftrue, Const) and isinstance(ite.iffalse, Const)
        assert ite.iftrue.value == 1 and ite.iffalse.value == 0xFFFFFFFF
        ite = opt.optimize(ite)
        assert isinstance(ite, ITE) and isinstance(ite.iftrue, Const) and isinstance(ite.iffalse, Const)
        assert ite.cond.likes(b) and ite.iftrue.value == 0xFFFFFFFF and ite.iffalse.value == 1


class TestX87StatusWord(unittest.TestCase):
    """fnstsw/sahf/test ah bit tests over CmpF fold into IEEE comparisons."""

    def setUp(self):
        from angr.analyses.decompiler.peephole_optimizations import X87CmpF

        self.opt = _make_peephole(X87CmpF)
        self.a = Tmp(None, 1, 64)
        self.b = Tmp(None, 2, 64)
        self.ftop = Tmp(None, 3, 16)
        self.eflags = Tmp(None, 4, 32)

    def _assert_cmp(self, result, op, a=None, b=None):
        assert isinstance(result, BinaryOp) and result.op == op and result.floating_point, result
        assert result.operands[0].likes(a or self.a) and result.operands[1].likes(b or self.b)

    def test_test_ah_0x41_je_is_gt(self):
        # test ah, 0x41; je  ->  a > b
        expr = _cmp_const("CmpEQ", _test_ah(_cmpf(self.a, self.b), self.ftop, 0x41), 0)
        self._assert_cmp(self.opt.optimize(expr), "CmpGT")

    def test_test_ah_0x45_jne_is_le(self):
        expr = _cmp_const("CmpNE", _test_ah(_cmpf(self.a, self.b), self.ftop, 0x45), 0)
        self._assert_cmp(self.opt.optimize(expr), "CmpLE")

    def test_test_ah_1_bit_is_lt(self):
        # (fsw >> 8) & 1 used as a value: C0 set -> a < b (or unordered)
        fsw = _fsw_ah(_cmpf(self.a, self.b), self.ftop)
        result = self.opt.optimize(_bit(Convert(None, 8, 32, False, fsw), 0))
        assert isinstance(result, Convert) and result.from_bits == 1 and result.to_bits == 32
        self._assert_cmp(result.operand, "CmpLT")

    def test_and_cmp_0x40_is_eq(self):
        # and ah, 0x45; cmp ah, 0x40; setne  ->  a != b
        masked = BinaryOp(None, "And", [_fsw_ah(_cmpf(self.a, self.b), self.ftop), Const(None, 0x45, 8)], False, bits=8)
        self._assert_cmp(self.opt.optimize(_cmp_const("CmpNE", masked, 0x40)), "CmpNE")
        self._assert_cmp(self.opt.optimize(_cmp_const("CmpEQ", masked, 0x40)), "CmpEQ")

    def test_sahf_zf_is_eq(self):
        # sahf; je: bit 6 of the copied flags, OF from the previous eflags stays unknown and is masked away
        eflags = _sahf_eflags(_cmpf(self.a, self.b), self.ftop, self.eflags)
        self._assert_cmp(self.opt.optimize(_cmp_const("CmpEQ", _bit(eflags, 6), 1)), "CmpEQ")

    def test_sahf_cf_or_zf_is_le(self):
        # sahf; jbe: (flags | flags >> 6) & 1
        eflags = _sahf_eflags(_cmpf(self.a, self.b), self.ftop, self.eflags)
        cf_or_zf = BinaryOp(
            None,
            "And",
            [
                BinaryOp(
                    None,
                    "Or",
                    [eflags, BinaryOp(None, "Shr", [eflags, Const(None, 6, 8)], False, bits=32)],
                    False,
                    bits=32,
                ),
                Const(None, 1, 32),
            ],
            False,
            bits=32,
        )
        self._assert_cmp(self.opt.optimize(_cmp_const("CmpEQ", cf_or_zf, 1)), "CmpLE")

    def test_fcomi_pf_is_isnan(self):
        # fucomi/ucomisd; jp: (CmpF & 0x45) >> 2 & 1
        masked = BinaryOp(None, "And", [_cmpf(self.a, self.b), Const(None, 0x45, 32)], False, bits=32)
        result = self.opt.optimize(_bit(masked, 2))
        assert isinstance(result, Convert) and result.from_bits == 1
        pred = result.operand
        assert isinstance(pred, BinaryOp) and pred.op == "CmpUN" and pred.floating_point
        assert pred.operands[0].likes(self.a) and pred.operands[1].likes(self.b)
        # a constant operand cannot be NaN
        masked = BinaryOp(None, "And", [_cmpf(self.a, Const(None, 0.0, 64)), Const(None, 0x45, 32)], False, bits=32)
        result = self.opt.optimize(_cmp_const("CmpNE", _bit(masked, 2), 0))
        assert isinstance(result, UnaryOp) and result.op == "IsNaN" and result.operand.likes(self.a)
        # a self-comparison can only be EQ or unordered: CF clear -> !isnan, ZF is always set
        masked = BinaryOp(None, "And", [_cmpf(self.a, self.a), Const(None, 0x45, 32)], False, bits=32)
        result = self.opt.optimize(_cmp_const("CmpEQ", _bit(masked, 0), 0))
        assert isinstance(result, UnaryOp) and result.op == "Not"
        assert isinstance(result.operand, UnaryOp) and result.operand.op == "IsNaN"
        result = self.opt.optimize(_cmp_const("CmpEQ", _bit(masked, 6), 1))
        assert isinstance(result, Const) and result.value == 1

    def test_propagated_constant_into_unordered(self):
        un = BinaryOp(None, "CmpUN", [Const(None, 0.0, 64), self.b], False, floating_point=True, bits=1)
        result = self.opt.optimize(un)
        assert isinstance(result, UnaryOp) and result.op == "IsNaN" and result.operand.likes(self.b)
        r = self.opt.optimize(UnaryOp(None, "IsNaN", Const(None, 1.5, 64), bits=1))
        assert isinstance(r, Const) and r.value == 0
        nan = struct.unpack("<d", struct.pack("<Q", 0x7FF8000000000000))[0]
        r = self.opt.optimize(UnaryOp(None, "IsNaN", Const(None, nan, 64), bits=1))
        assert isinstance(r, Const) and r.value == 1
        r = self.opt.optimize(UnaryOp(None, "IsNaN", Const(None, 0x7FF8000000000001, 64), bits=1))
        assert isinstance(r, Const) and r.value == 1

    def _fp(self, op, a, b):
        return BinaryOp(None, op, [a, b], False, floating_point=True, bits=1)

    def test_redundant_unordered_guard(self):
        # ucomisd; sete; setnp; and: (a == b) & !isunordered(a, b) is a == b
        eq = self._fp("CmpEQ", self.a, self.b)
        ordered = UnaryOp(None, "Not", self._fp("CmpUN", self.a, self.b), bits=1)
        expr = BinaryOp(
            None, "And", [Convert(None, 1, 8, False, eq), Convert(None, 1, 8, False, ordered)], False, bits=8
        )
        result = self.opt.optimize(expr)
        assert isinstance(result, Convert) and result.from_bits == 1 and result.to_bits == 8
        self._assert_cmp(result.operand, "CmpEQ")
        # jne/jp: a != b || isnan(a) || isnan(b) is a != b
        ne = self._fp("CmpNE", self.a, self.b)
        nan_a = UnaryOp(None, "IsNaN", self.a, bits=1)
        nan_b = UnaryOp(None, "IsNaN", self.b, bits=1)
        expr = BinaryOp(
            None, "LogicalOr", [BinaryOp(None, "LogicalOr", [ne, nan_a], False, bits=1), nan_b], False, bits=1
        )
        self._assert_cmp(self.opt.optimize(expr), "CmpNE")
        # !isnan(a) alone guards a comparison against a constant
        zero = Const(None, 0.0, 64)
        lt = self._fp("CmpLT", self.a, zero)
        not_nan_a = UnaryOp(None, "Not", nan_a, bits=1)
        self._assert_cmp(
            self.opt.optimize(BinaryOp(None, "LogicalAnd", [not_nan_a, lt], False, bits=1)), "CmpLT", b=zero
        )

    def test_needed_unordered_guard_is_kept(self):
        nan_a = UnaryOp(None, "IsNaN", self.a, bits=1)
        un = self._fp("CmpUN", self.a, self.b)
        # b may be NaN
        expr = BinaryOp(
            None, "LogicalAnd", [self._fp("CmpLT", self.a, self.b), UnaryOp(None, "Not", nan_a, bits=1)], False, bits=1
        )
        assert self.opt.optimize(expr) is None
        # a == b is false when unordered: a == b || isunordered(a, b) is not a == b
        assert (
            self.opt.optimize(BinaryOp(None, "LogicalOr", [self._fp("CmpEQ", self.a, self.b), un], False, bits=1))
            is None
        )
        # !(a < b) is true when unordered
        not_lt = UnaryOp(None, "Not", self._fp("CmpLT", self.a, self.b), bits=1)
        assert (
            self.opt.optimize(BinaryOp(None, "LogicalAnd", [not_lt, UnaryOp(None, "Not", un, bits=1)], False, bits=1))
            is None
        )

    def test_ftop_bits_block_the_fold(self):
        # test ah, 0x08 reads the ftop bits: not a CmpF test
        expr = _cmp_const("CmpEQ", _test_ah(_cmpf(self.a, self.b), self.ftop, 0x08), 0)
        assert self.opt.optimize(expr) is None

    def test_two_different_cmpf_block_the_fold(self):
        c = Tmp(None, 5, 64)
        lhs = BinaryOp(None, "And", [_cmpf(self.a, self.b), Const(None, 1, 32)], False, bits=32)
        rhs = BinaryOp(None, "And", [_cmpf(self.a, c), Const(None, 1, 32)], False, bits=32)
        expr = _cmp_const("CmpEQ", BinaryOp(None, "Or", [lhs, rhs], False, bits=32), 0)
        assert self.opt.optimize(expr) is None


def _fxam(x):
    return Call(None, "__fxam", args=[x], bits=32)


def _fxam_ah(x, ftop):
    """(char)(((ftop & 7) * 0x800 | (unsigned short)__fxam(x) & 0x4700) >> 8), as lifted from fxam; fnstsw ax."""
    ftop_part = BinaryOp(
        None,
        "Mul",
        [BinaryOp(None, "And", [ftop, Const(None, 7, 16)], False, bits=16), Const(None, 0x800, 16)],
        False,
        bits=16,
    )
    fc3210 = BinaryOp(None, "And", [Convert(None, 32, 16, False, _fxam(x)), Const(None, 0x4700, 16)], False, bits=16)
    fsw = BinaryOp(None, "Or", [ftop_part, fc3210], False, bits=16)
    return Convert(None, 16, 8, False, BinaryOp(None, "Shr", [fsw, Const(None, 8, 8)], False, bits=16))


class TestX87Fxam(unittest.TestCase):
    """Tests of fxam status bits fold into classification predicates (Intel SDM FXAM table)."""

    def setUp(self):
        from angr.analyses.decompiler.peephole_optimizations import X87CmpF

        self.opt = _make_peephole(X87CmpF)
        self.x = Tmp(None, 1, 64)
        self.ftop = Tmp(None, 3, 16)

    def _masked_cmp(self, op, mask, value):
        masked = BinaryOp(None, "And", [_fxam_ah(self.x, self.ftop), Const(None, mask, 8)], False, bits=8)
        return self.opt.optimize(_cmp_const(op, masked, value))

    def _assert_unary(self, result, op, negated=False):
        if negated:
            assert isinstance(result, UnaryOp) and result.op == "Not", result
            result = result.operand
        assert isinstance(result, UnaryOp) and result.op == op and result.operand.likes(self.x), result

    def test_class_compares(self):
        # and ah, 0x45; cmp ah, imm: C3/C2/C0 = 001 NaN, 101 infinity, 100 zero, 010 normal
        self._assert_unary(self._masked_cmp("CmpEQ", 0x45, 0x01), "IsNaN")
        self._assert_unary(self._masked_cmp("CmpNE", 0x45, 0x01), "IsNaN", negated=True)
        self._assert_unary(self._masked_cmp("CmpEQ", 0x45, 0x05), "IsInf")
        self._assert_unary(self._masked_cmp("CmpEQ", 0x45, 0x04), "IsNormal")
        zero = self._masked_cmp("CmpEQ", 0x45, 0x40)
        assert isinstance(zero, BinaryOp) and zero.op == "CmpEQ" and zero.floating_point, zero
        assert zero.operands[0].likes(self.x) and zero.operands[1].value == 0.0
        nonzero = self._masked_cmp("CmpNE", 0x45, 0x40)
        assert isinstance(nonzero, BinaryOp) and nonzero.op == "CmpNE" and nonzero.floating_point, nonzero

    def test_bit_tests(self):
        # test ah, 1 (C0): NaN or infinity; test ah, 2 (C1): the sign
        self._assert_unary(self._masked_cmp("CmpNE", 0x01, 0), "IsFinite", negated=True)
        self._assert_unary(self._masked_cmp("CmpEQ", 0x01, 0), "IsFinite")
        self._assert_unary(self._masked_cmp("CmpNE", 0x02, 0), "SignBit")
        self._assert_unary(self._masked_cmp("CmpEQ", 0x02, 0), "SignBit", negated=True)

    def test_unspellable_class_set(self):
        # test ah, 0x40 (C3): zero or denormal has no C predicate
        assert self._masked_cmp("CmpNE", 0x40, 0) is None
        # C0 and the sign together
        assert self._masked_cmp("CmpEQ", 0x03, 0x03) is None
        # the ftop bits are not known
        assert self._masked_cmp("CmpEQ", 0x08, 0) is None

    def test_vex_ccall_source(self):
        # calculate_FXAM before the ccall rewriter ran
        from angr.ailment.expression import Reinterpret, VEXCCallExpression

        ccall = VEXCCallExpression(
            None,
            "x86g_calculate_FXAM",
            [Const(None, 1, 32), Reinterpret(None, 64, "F", 64, "I", self.x)],
            bits=32,
        )
        masked = BinaryOp(
            None,
            "And",
            [
                Convert(None, 32, 8, False, BinaryOp(None, "Shr", [ccall, Const(None, 8, 8)], False, bits=32)),
                Const(None, 0x45, 8),
            ],
            False,
            bits=8,
        )
        self._assert_unary(self.opt.optimize(_cmp_const("CmpEQ", masked, 0x05)), "IsInf")

    def test_status_word_stored_to_memory(self):
        # fnstsw word [ebp-0xa0]; test byte [ebp-0x9f], 1
        from angr.ailment.block import Block
        from angr.ailment.expression import Load
        from angr.ailment.statement import ConditionalJump, Store

        ebp = Tmp(None, 9, 32)

        def addr(off):
            return BinaryOp(None, "Sub", [ebp, Const(None, off, 32)], False, bits=32)

        fsw = BinaryOp(
            None,
            "Or",
            [
                Const(None, 0x3800, 16),
                BinaryOp(
                    None, "And", [Convert(None, 32, 16, False, _fxam(self.x)), Const(None, 0x4700, 16)], False, bits=16
                ),
            ],
            False,
            bits=16,
        )
        store = Store(None, addr(0xA0), fsw, 2, "Iend_LE")
        load = Load(None, addr(0x9F), 1, "Iend_LE")
        cond = _cmp_const("CmpNE", BinaryOp(None, "And", [load, Const(None, 1, 8)], False, bits=8), 0)
        block = Block(0x1000, 8, statements=[store, ConditionalJump(None, cond, Const(None, 0x2000, 32), None)])
        self._assert_unary(self.opt.optimize(cond, stmt_idx=1, block=block), "IsFinite", negated=True)

        # an intervening store to an unrelated address may alias
        other = Store(None, Tmp(None, 10, 32), Const(None, 0, 8), 1, "Iend_LE")
        block = Block(0x1000, 8, statements=[store, other, ConditionalJump(None, cond, Const(None, 0x2000, 32), None)])
        assert self.opt.optimize(cond, stmt_idx=2, block=block) is None
        # a store that does not cover the loaded byte
        short = Store(None, addr(0xA0), Convert(None, 16, 8, False, fsw), 1, "Iend_LE")
        block = Block(0x1000, 8, statements=[short, ConditionalJump(None, cond, Const(None, 0x2000, 32), None)])
        assert self.opt.optimize(cond, stmt_idx=1, block=block) is None


class TestCmpFValueLowering(unittest.TestCase):
    """A CmpF that survives as a value is lowered to an exact chain of IEEE tests."""

    def setUp(self):
        from angr.ailment.manager import Manager

        self.mgr = Manager()
        self.a = Tmp(None, 1, 64)
        self.b = Tmp(None, 2, 64)

    def _lower(self, expr):
        from angr.analyses.decompiler.x87_fsw import lower_cmpf_value

        return lower_cmpf_value(expr, self.mgr)

    @staticmethod
    def _fsw(cmpf, ftop_bits):
        """ftop_bits | CmpF * 0x100 & 0x4500 & 0x4700, as stored by fnstsw m16 / ftst."""
        c3210 = BinaryOp(
            None,
            "And",
            [
                BinaryOp(None, "Mul", [Convert(None, 32, 16, False, cmpf), Const(None, 0x100, 16)], False, bits=16),
                Const(None, 0x4500, 16),
            ],
            False,
            bits=16,
        )
        c3210 = BinaryOp(None, "And", [c3210, Const(None, 0x4700, 16)], False, bits=16)
        return BinaryOp(None, "Or", [ftop_bits, c3210], False, bits=16)

    def _assert_chain(self, expr, expected):
        """expected: [(cond_op, operands, value), ..., default]"""
        for cond_op, operands, value in expected[:-1]:
            assert isinstance(expr, ITE), expr
            cond = expr.cond
            if cond_op == "IsNaN":
                assert isinstance(cond, UnaryOp) and cond.op == "IsNaN" and cond.operand.likes(operands[0]), cond
            else:
                assert isinstance(cond, BinaryOp) and cond.op == cond_op and cond.floating_point, cond
                assert all(x.likes(y) for x, y in zip(cond.operands, operands, strict=True)), cond
            assert isinstance(expr.iftrue, Const) and expr.iftrue.value == value, expr
            expr = expr.iffalse
        last = expected[-1]
        if isinstance(last, int):
            assert isinstance(expr, Const) and expr.value == last, expr
        else:
            cond_op, operands = last
            assert isinstance(expr, Convert) and expr.from_bits == 1, expr
            assert (
                isinstance(expr.operand, BinaryOp)
                and expr.operand.op == cond_op
                and all(x.likes(y) for x, y in zip(expr.operand.operands, operands, strict=True))
            ), expr

    def test_ftst_status_word(self):
        # 0x3800 | CmpF(a, 0.0) * 0x100 & 0x4500 & 0x4700: the masks fold away, the ftop constant stays
        zero = Const(None, 0.0, 64)
        result = self._lower(self._fsw(_cmpf(self.a, zero), Const(None, 0x3800, 16)))
        assert isinstance(result, BinaryOp) and result.op == "Or" and result.bits == 16, result
        assert isinstance(result.operands[0], Const) and result.operands[0].value == 0x3800
        a0 = (self.a, zero)
        self._assert_chain(result.operands[1], [("IsNaN", a0, 0x4500), ("CmpEQ", a0, 0x4000), ("CmpLT", a0, 0x100), 0])

    def test_operand_order(self):
        # CmpF(b, a) & 0x45: LT means b < a
        masked = BinaryOp(None, "And", [_cmpf(self.b, self.a), Const(None, 0x45, 32)], False, bits=32)
        ba = (self.b, self.a)
        self._assert_chain(self._lower(masked), [("CmpUN", ba, 0x45), ("CmpEQ", ba, 0x40), ("CmpLT", ba)])

    def test_nan_operand(self):
        nan = Const(None, 0x7FF8000000000000, 64)
        masked = BinaryOp(None, "And", [_cmpf(self.a, nan), Const(None, 0x45, 32)], False, bits=32)
        result = self._lower(masked)
        assert isinstance(result, Const) and result.value == 0x45, result

    def test_same_operands(self):
        masked = BinaryOp(None, "And", [_cmpf(self.a, self.a), Const(None, 0x45, 32)], False, bits=32)
        self._assert_chain(self._lower(masked), [("IsNaN", (self.a,), 0x45), 0x40])

    def test_unknown_bits_not_lowered(self):
        # the ftop bits are unknown: only the CmpF part can be lowered
        ftop = BinaryOp(None, "Mul", [Tmp(None, 3, 16), Const(None, 0x800, 16)], False, bits=16)
        assert self._lower(self._fsw(_cmpf(self.a, self.b), ftop)) is None
        assert self._lower(Tmp(None, 3, 32)) is None


class TestControlWordReadCCall(unittest.TestCase):
    """stmxcsr / fnstcw: create_mxcsr(sseround) and create_fpucw(fpround) become _mm_getcsr() and __fnstcw()."""

    def _rewrite(self, arch: str, callee: str, rename: bool = False):
        from angr.ailment.expression import Call, VEXCCallExpression
        from angr.ailment.manager import Manager
        from angr.analyses.decompiler.ccall_rewriters import CCALL_REWRITERS

        proj = angr.load_shellcode(b"\xc3", arch)
        bits = proj.arch.bits
        ccall = VEXCCallExpression(None, callee, [Tmp(None, 1, bits)], bits=bits)
        if rename:
            ccall = VEXCCallExpression(None, "_ccall", [Tmp(None, 1, bits)], bits=bits, vex_callee=callee)
        result = CCALL_REWRITERS[proj.arch.name](ccall, proj, Manager()).result
        assert result is not None and result.bits == bits
        call = result.operand if isinstance(result, Convert) else result
        assert isinstance(call, Call) and not call.args, result
        return result, call

    def test_x86_mxcsr(self):
        result, call = self._rewrite("x86", "x86g_create_mxcsr")
        assert call is result and call.target == "_mm_getcsr"

    def test_x86_fpucw(self):
        result, call = self._rewrite("x86", "x86g_create_fpucw")
        assert isinstance(result, Convert) and result.from_bits == 16 and call.target == "__fnstcw"

    def test_x86_renamed_ccall(self):
        _, call = self._rewrite("x86", "x86g_create_fpucw", rename=True)
        assert call.target == "__fnstcw"

    def test_amd64(self):
        result, call = self._rewrite("amd64", "amd64g_create_mxcsr")
        assert isinstance(result, Convert) and result.from_bits == 32 and call.target == "_mm_getcsr"
        _, call = self._rewrite("amd64", "amd64g_create_fpucw")
        assert call.target == "__fnstcw"


class TestX86FPConditionCCall(unittest.TestCase):
    """x86g_calculate_condition over flags derived from an x87 status word."""

    def setUp(self):
        from angr.ailment.manager import Manager

        self.proj = angr.load_shellcode(b"\xc3", "x86")
        self.mgr = Manager()
        self.a = Tmp(None, 1, 64)
        self.b = Tmp(None, 2, 64)
        self.ftop = Tmp(None, 3, 16)
        self.eflags = Tmp(None, 4, 32)

    def _rewrite(self, cond, op, dep1, dep2: int | Expression = 0, ndep: int | Expression = 0):
        from angr.ailment.expression import VEXCCallExpression
        from angr.analyses.decompiler.ccall_rewriters import X86CCallRewriter

        dep2 = Const(None, dep2, 32) if isinstance(dep2, int) else dep2
        ndep = Const(None, ndep, 32) if isinstance(ndep, int) else ndep
        ccall = VEXCCallExpression(
            None, "x86g_calculate_condition", [Const(None, cond, 32), Const(None, op, 32), dep1, dep2, ndep], bits=32
        )
        return X86CCallRewriter(ccall, self.proj, self.mgr).result

    def _assert_cmp(self, result, op):
        assert isinstance(result, Convert) and result.from_bits == 1 and result.to_bits == 32, result
        pred = result.operand
        assert isinstance(pred, BinaryOp) and pred.op == op and pred.floating_point, pred
        assert pred.operands[0].likes(self.a) and pred.operands[1].likes(self.b)

    def test_test_ah_5_jp_is_ge(self):
        # MSVC `if (a < b)`: test ah, 5; jp skip  ->  skip when a >= b
        self._assert_cmp(self._rewrite(10, 13, _test_ah(_cmpf(self.a, self.b), self.ftop, 5)), "CmpGE")

    def test_test_ah_0x44_jnp_is_eq(self):
        self._assert_cmp(self._rewrite(11, 13, _test_ah(_cmpf(self.a, self.b), self.ftop, 0x44)), "CmpEQ")

    def test_test_ah_0x41_jne_is_le(self):
        self._assert_cmp(self._rewrite(5, 13, _test_ah(_cmpf(self.a, self.b), self.ftop, 0x41)), "CmpLE")

    def test_sahf_jbe_is_le(self):
        # CondBE over copied flags (sahf)
        self._assert_cmp(self._rewrite(6, 0, _sahf_eflags(_cmpf(self.a, self.b), self.ftop, self.eflags)), "CmpLE")

    def test_fcomi_ja_is_gt(self):
        # fcomi: cc_dep1 = CmpF & 0x45; CondNBE
        masked = BinaryOp(None, "And", [_cmpf(self.a, self.b), Const(None, 0x45, 32)], False, bits=32)
        self._assert_cmp(self._rewrite(7, 0, masked), "CmpGT")

    def test_cmp_ah_0x40_je_is_eq(self):
        # and ah, 0x45; cmp ah, 0x40; je  (CondZ, SUBB)
        masked = BinaryOp(None, "And", [_fsw_ah(_cmpf(self.a, self.b), self.ftop), Const(None, 0x45, 8)], False, bits=8)
        self._assert_cmp(self._rewrite(4, 4, Convert(None, 8, 32, False, masked), 0x40), "CmpEQ")

    def test_fxam_sahf_jb_is_not_finite(self):
        # fxam; fnstsw ax; sahf; jb: CF = C0, set for NaN and infinity
        eax = Insert(
            None,
            Insert(None, Const(None, 0, 32), Const(None, 0, 32), Const(None, 0, 8), "Iend_LE"),
            Const(None, 1, 32),
            _fxam_ah(self.a, self.ftop),
            "Iend_LE",
        )
        eflags = BinaryOp(
            None,
            "Or",
            [
                BinaryOp(None, "And", [self.eflags, Const(None, 0x800, 32)], False, bits=32),
                BinaryOp(
                    None,
                    "And",
                    [BinaryOp(None, "Shr", [eax, Const(None, 8, 8)], False, bits=32), Const(None, 0xD5, 32)],
                    False,
                    bits=32,
                ),
            ],
            False,
            bits=32,
        )
        result = self._rewrite(2, 0, eflags)
        assert isinstance(result, Convert) and result.from_bits == 1, result
        pred = result.operand
        assert isinstance(pred, UnaryOp) and pred.op == "Not", pred
        assert (
            isinstance(pred.operand, UnaryOp) and pred.operand.op == "IsFinite" and pred.operand.operand.likes(self.a)
        )

    def test_integer_parity_is_left_alone(self):
        # inc edi; jp with the x87 carry only in ndep: a real parity test, not a comparison
        dep1 = BinaryOp(None, "Add", [Tmp(None, 6, 32), Const(None, 1, 32)], False, bits=32)
        ndep = BinaryOp(None, "And", [_cmpf(self.a, self.b), Const(None, 1, 32)], False, bits=32)
        assert self._rewrite(10, 18, dep1, 0, ndep) is None


class TestRemoveIntFPIntRoundTrip(unittest.TestCase):
    """Conv(F->sN, Conv(sN->F, x)) folds only when the int -> FP conversion is exact."""

    @staticmethod
    def _opt(arch, int_bits, fp_bits=64):
        from angr.ailment.manager import Manager
        from angr.analyses.decompiler.peephole_optimizations.remove_int_fp_int_roundtrip import (
            RemoveIntFPIntRoundTrip,
        )

        proj = angr.load_shellcode(b"\xc3", arch)
        opt = RemoveIntFPIntRoundTrip(proj, proj.kb, ail_manager=Manager(), func_addr=0)
        x = Tmp(1, 0, int_bits)
        inner = Convert(2, int_bits, fp_bits, True, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP)
        outer = Convert(3, fp_bits, int_bits, True, inner, from_type=Convert.TYPE_FP, to_type=Convert.TYPE_INT)
        return opt.optimize(outer), x

    def test_int64_x87(self):
        # 32-bit x86: I64StoF64 is fild, exact through the 80-bit format
        result, x = self._opt("x86", 64)
        assert result is not None and result.likes(x)

    def test_int64_sse_not_folded(self):
        # amd64: cvtsi2sd rax rounds int64 values beyond 2**53
        result, _ = self._opt("amd64", 64)
        assert result is None

    def test_int32_exact_in_double(self):
        result, x = self._opt("amd64", 32)
        assert result is not None and result.likes(x)

    def test_int32_not_exact_in_float(self):
        result, _ = self._opt("amd64", 32, fp_bits=32)
        assert result is None


class TestSimplifyMaskedInsert(unittest.TestCase):
    """Masked reads of Insert drop the part of the Insert they cannot see."""

    def setUp(self):
        from angr.analyses.decompiler.peephole_optimizations import SimplifyMaskedInsert

        self.opt = _make_peephole(SimplifyMaskedInsert)
        self.base = Tmp(None, 1, 32)
        self.byte = Tmp(None, 2, 8)

    def _ins(self, offset, value=None):
        return Insert(None, self.base, Const(None, offset, 64), value or self.byte, "Iend_LE")

    @staticmethod
    def _and(expr, mask):
        return BinaryOp(None, "And", [expr, Const(None, mask, expr.bits)], False, bits=expr.bits)

    def test_and_sees_only_the_value(self):
        # mov al, [m]; and eax, 0xf: _INSERT(x, 0, byte) & 0xffff & 15 -> byte & 15
        result = self.opt.optimize(self._and(self._and(self._ins(0), 0xFFFF), 15))
        assert isinstance(result, BinaryOp) and result.op == "And" and result.operands[1].value == 15, result
        conv = result.operands[0]
        assert (
            isinstance(conv, Convert) and conv.from_bits == 8 and conv.to_bits == 32 and conv.operand.likes(self.byte)
        )
        # at byte 1 the value is shifted into place
        result = self.opt.optimize(self._and(self._ins(1), 0xF00))
        assert isinstance(result, BinaryOp) and result.op == "And" and result.operands[1].value == 0xF00, result
        shl = result.operands[0]
        assert isinstance(shl, BinaryOp) and shl.op == "Shl" and shl.operands[1].value == 8, shl

    def test_and_sees_only_the_base(self):
        result = self.opt.optimize(self._and(self._ins(1), 0xFFFF00FF))
        assert isinstance(result, BinaryOp) and result.operands[0].likes(self.base), result
        assert result.operands[1].value == 0xFFFF00FF

    def test_and_sees_both(self):
        assert self.opt.optimize(self._and(self._ins(0), 0x1FF)) is None
        assert self.opt.optimize(self._and(self.base, 0xF)) is None

    def test_fp_value_is_not_converted(self):
        fp = UnaryOp(None, "Neg", Tmp(None, 3, 32), bits=32, floating_point=True)
        ins = Insert(None, Tmp(None, 4, 64), Const(None, 0, 64), fp, "Iend_LE")
        assert self.opt.optimize(self._and(ins, 0xFF)) is None

    def test_extract(self):
        ins = Insert(None, self.base, Const(None, 1, 64), Tmp(None, 5, 16), "Iend_LE")
        # the whole value
        result = self.opt.optimize(Extract(None, 16, ins, Const(None, 1, 64), "Iend_LE"))
        assert isinstance(result, Tmp) and result.tmp_idx == 5, result
        # one byte of the value
        result = self.opt.optimize(Extract(None, 8, ins, Const(None, 2, 64), "Iend_LE"))
        assert isinstance(result, Extract) and result.base.likes(ins.value) and result.offset.value == 1, result
        # bytes of the base only
        result = self.opt.optimize(Extract(None, 8, ins, Const(None, 3, 64), "Iend_LE"))
        assert isinstance(result, Extract) and result.base.likes(self.base) and result.offset.value == 3, result
        # straddling
        assert self.opt.optimize(Extract(None, 16, ins, Const(None, 0, 64), "Iend_LE")) is None

    def test_truncation(self):
        result = self.opt.optimize(Convert(None, 32, 8, False, self._ins(0)))
        assert isinstance(result, Tmp) and result.likes(self.byte), result
        result = self.opt.optimize(Convert(None, 32, 8, False, self._ins(1)))
        assert isinstance(result, Convert) and result.operand.likes(self.base), result
        assert self.opt.optimize(Convert(None, 32, 16, False, self._ins(0))) is None

    def test_truncation_preserves_extra_def(self):
        vvar = VirtualVariable(1, 10, 32, category=VirtualVariableCategory.STACK, oident=-4)
        reference = UnaryOp(2, "Reference", vvar, bits=32, extra_def=True)
        inserted = Insert(3, reference, Const(4, 0, 64), self.byte, "Iend_LE")

        assert self.opt.optimize(Convert(5, 32, 8, False, inserted)) is None


class TestFloat32Repr(unittest.TestCase):
    def test_flt_max_does_not_overflow(self):
        from angr.analyses.decompiler.structured_codegen.c import _float32_repr

        flt_max = struct.unpack("f", struct.pack("I", 0x7F7FFFFF))[0]
        literal = _float32_repr(flt_max)
        assert struct.unpack("f", struct.pack("f", float(literal)))[0] == flt_max
        assert _float32_repr(0.72) == "0.72"


class TestFPExactIdentities(unittest.TestCase):
    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.fp_exact_identities import FPExactIdentities

        return _make_peephole(FPExactIdentities).optimize(expr)

    @staticmethod
    def _fp(idx, op, a, b, bits=64):
        return BinaryOp(idx, op, [a, b], True, floating_point=True, bits=bits)

    def test_mul_one(self):
        x = Tmp(1, 0, 64)
        r = self._opt(self._fp(2, "Mul", Const(3, 1.0, 64), x))
        assert r is not None and r.likes(x)
        r = self._opt(self._fp(2, "Mul", x, Const(3, 1.0, 64)))
        assert r is not None and r.likes(x)
        # integer bit pattern of 1.0f
        x32 = Tmp(1, 0, 32)
        r = self._opt(self._fp(2, "Mul", x32, Const(3, 0x3F800000, 32), bits=32))
        assert r is not None and r.likes(x32)
        assert self._opt(self._fp(2, "Mul", x, Const(3, 2.0, 64))) is None

    def test_f2xm1_add_one(self):
        exp2 = UnaryOp(2, "Exp2", Tmp(1, 0, 64), bits=64)
        f2xm1 = self._fp(3, "Sub", exp2, Const(4, 1.0, 64))
        r = self._opt(self._fp(5, "Add", f2xm1, Const(6, 1.0, 64)))
        assert r is not None and r.likes(exp2)
        r = self._opt(self._fp(5, "Add", Const(6, 1.0, 64), f2xm1))
        assert r is not None and r.likes(exp2)

    def test_inexact_shapes_not_folded(self):
        # (x - 1.0) + 1.0 absorbs a tiny x
        x = Tmp(1, 0, 64)
        sub = self._fp(3, "Sub", x, Const(4, 1.0, 64))
        assert self._opt(self._fp(5, "Add", sub, Const(6, 1.0, 64))) is None
        # integer arithmetic is left to the integer simplifiers
        imul = BinaryOp(7, "Mul", [x, Const(8, 1, 64)], False, bits=64)
        assert self._opt(imul) is None


class TestFswEvaluatorMemo(unittest.TestCase):
    """Definitions form a DAG; the known-bits evaluator must memoize shared vvars instead of re-walking every path."""

    @staticmethod
    def _vv(varid: int, bits: int = 32) -> VirtualVariable:
        return VirtualVariable(varid + 1000, varid, bits, category=VirtualVariableCategory.REGISTER, oident=16)

    def test_shared_definitions_evaluate_in_linear_time(self):
        from angr.analyses.decompiler.x87_fsw import CMPF_OUTCOMES, evaluate_over_fsw

        a, b = self._vv(100, 64), self._vv(101, 64)
        defs: dict[int, Expression] = {0: BinaryOp(None, "CmpF", [a, b], False, bits=32, floating_point=True)}
        for i in range(1, 16):  # (x | x) | (x | x) keeps the value; 4^15 paths without memoization, depth 45
            half = BinaryOp(None, "Or", [self._vv(i - 1), self._vv(i - 1)], False, bits=32)
            defs[i] = BinaryOp(None, "Or", [half, half], False, bits=32)
        expr = BinaryOp(None, "And", [self._vv(15), Const(None, 0x45, 32)], False, bits=32)

        start = time.time()
        table = evaluate_over_fsw([expr], defs)
        assert time.time() - start < 2.0
        assert table is not None
        assert table.values == {o: (o & 0x45,) for o in CMPF_OUTCOMES}

    def test_node_budget_gives_up_on_huge_expressions(self):
        from angr.analyses.decompiler.x87_fsw import evaluate_over_fsw

        a, b = self._vv(100, 64), self._vv(101, 64)
        defs: dict[int, Expression] = {0: BinaryOp(None, "CmpF", [a, b], False, bits=32, floating_point=True)}
        expr: Expression = self._vv(0)
        for i in range(1, 400):
            defs[i] = Const(None, i, 32)
            expr = BinaryOp(None, "Xor", [expr, self._vv(i)], False, bits=32)
        assert evaluate_over_fsw([expr], defs) is None
