"""Unit tests for FP-related peephole optimizations.

Tests peephole logic directly by constructing AIL expressions,
without running the full decompiler pipeline.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import struct
import unittest

import angr
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Convert,
    Extract,
    Insert,
    Tmp,
    UnaryOp,
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


class TestRemoveRedundantConversions(unittest.TestCase):
    """Test redundant Conv elimination for FP patterns."""

    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.remove_redundant_conversions import (
            RemoveRedundantConversions,
        )

        opt = _make_peephole(RemoveRedundantConversions)
        return opt.optimize(expr)

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
        block = Block(0x400000, 12, statements=stmts)
        assert opt.optimize(stmts[2], 2, block) is None


if __name__ == "__main__":
    unittest.main()
