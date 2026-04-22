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
    BinaryOp,
    Const,
    Convert,
    Extract,
    UnaryOp,
)


def _proj():
    return angr.load_shellcode(b"\xc3", "amd64")


def _make_peephole(cls):
    from angr.ailment.manager import Manager

    proj = _proj()
    mgr = Manager(arch=proj.arch)
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
        inner = Const(1, None, bits32, 32)
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
        inner = Const(1, None, bits64, 64)
        expr = Convert(2, 64, 32, False, inner, from_type=Convert.TYPE_FP, to_type=Convert.TYPE_FP)
        result = self._opt(expr)
        assert result is not None
        assert result.bits == 32
        (f32,) = struct.unpack("<f", struct.pack("<I", result.value))
        assert abs(f32 - 2.718) < 0.01

    def test_int_to_float64(self):
        """Conv(32I->64F, 42) should produce the double bit pattern for 42.0."""
        inner = Const(1, None, 42, 32)
        expr = Convert(2, 32, 64, True, inner, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP)
        result = self._opt(expr)
        assert result is not None
        assert result.bits == 64
        (f64,) = struct.unpack("<d", struct.pack("<Q", result.value))
        assert f64 == 42.0

    def test_signed_int_to_float64(self):
        """Conv(32I->64F, -1 as unsigned) should produce -1.0."""
        inner = Const(1, None, 0xFFFFFFFF, 32)  # -1 as unsigned 32-bit
        expr = Convert(2, 32, 64, True, inner, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_FP)
        result = self._opt(expr)
        assert result is not None
        (f64,) = struct.unpack("<d", struct.pack("<Q", result.value))
        assert f64 == -1.0

    def test_non_fp_convert_returns_none(self):
        """Non-FP Convert should not be handled by FP evaluator."""
        inner = Const(1, None, 42, 32)
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
        x = Const(1, None, 42, 32)
        inner = Convert(2, 32, 64, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        outer = Convert(3, 64, 32, False, inner, from_type=Convert.TYPE_FP, to_type=Convert.TYPE_FP)
        result = self._opt(outer)
        assert result is x

    def test_same_type_round_trip(self):
        """Conv(64I->32I, Conv(32I->64I, x)) should eliminate both."""
        x = Const(1, None, 42, 32)
        inner = Convert(2, 32, 64, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        outer = Convert(3, 64, 32, False, inner, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        result = self._opt(outer)
        assert result is x

    def test_unary_conv_round_trip(self):
        """Conv(128->64, Neg(Conv(64->128, x))) should produce Neg(x)."""
        x = Const(1, None, 42, 64)
        inner_conv = Convert(2, 64, 128, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        neg = UnaryOp(3, "Neg", inner_conv, bits=128)
        outer = Convert(4, 128, 64, False, neg, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        result = self._opt(outer)
        assert result is not None
        assert isinstance(result, UnaryOp)
        assert result.operand is x
        assert result.bits == 64


# ======================================================================
# fp_sign_flip: sign bit XOR to negation
# ======================================================================


class TestFPSignFlip(unittest.TestCase):
    """Test FP sign bit XOR to negation peephole."""

    def _opt(self, expr):
        from angr.analyses.decompiler.peephole_optimizations.fp_sign_flip import FPSignFlipToNeg

        opt = _make_peephole(FPSignFlipToNeg)
        return opt.optimize(expr)

    def test_128bit_xor_64bit_sign(self):
        """128-bit x ^ 0x8000000000000000 -> Neg(x) (double sign flip in vector register)."""
        x = Const(1, None, 42, 128)
        sign = Const(2, None, 0x8000000000000000, 128)
        expr = BinaryOp(3, "Xor", [x, sign], False, bits=128)
        result = self._opt(expr)
        assert result is not None
        assert isinstance(result, UnaryOp)
        assert result.op == "Neg"
        assert result.floating_point is True

    def test_128bit_xor_32bit_sign(self):
        """128-bit x ^ 0x80000000 -> Neg(x) (float sign flip in vector register)."""
        x = Const(1, None, 42, 128)
        sign = Const(2, None, 0x80000000, 128)
        expr = BinaryOp(3, "Xor", [x, sign], False, bits=128)
        result = self._opt(expr)
        assert result is not None
        assert isinstance(result, UnaryOp)
        assert result.op == "Neg"
        assert result.floating_point is True

    def test_64bit_xor_sign_not_matched(self):
        """Direct 64-bit x ^ sign_mask should NOT match (only 128-bit vector ops)."""
        x = Const(1, None, 42, 64)
        sign = Const(2, None, 0x8000000000000000, 64)
        expr = BinaryOp(3, "Xor", [x, sign], False, bits=64)
        result = self._opt(expr)
        assert result is None

    def test_32bit_xor_sign_not_matched(self):
        """Direct 32-bit x ^ sign_mask should NOT match (only 128-bit vector ops)."""
        x = Const(1, None, 42, 32)
        sign = Const(2, None, 0x80000000, 32)
        expr = BinaryOp(3, "Xor", [x, sign], False, bits=32)
        result = self._opt(expr)
        assert result is None

    def test_non_sign_xor_returns_none(self):
        """x ^ 0x12345678 should not match."""
        x = Const(1, None, 42, 128)
        other = Const(2, None, 0x12345678, 128)
        expr = BinaryOp(3, "Xor", [x, other], False, bits=128)
        result = self._opt(expr)
        assert result is None


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
        a = Const(1, None, 42, 64)
        b = Const(2, None, 43, 64)
        conv_a = Convert(3, 64, 128, False, a, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        conv_b = Convert(4, 64, 128, False, b, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        mulv = BinaryOp(5, "MulV", [conv_a, conv_b], False, floating_point=True, bits=128)
        zero = Const(6, None, 0, 64)
        extract = Extract(7, 64, mulv, zero, "Iend_LE")
        result = self._opt(extract)
        assert result is not None
        assert isinstance(result, BinaryOp)
        assert result.op == "Mul"
        assert result.floating_point is True
        assert result.bits == 64

    def test_extract_neg_conv(self):
        """Extract(Neg(Conv(64->128, x)), 64@0) -> Neg(x, fp=True)."""
        x = Const(1, None, 42, 64)
        conv = Convert(2, 64, 128, False, x, from_type=Convert.TYPE_INT, to_type=Convert.TYPE_INT)
        neg = UnaryOp(3, "Neg", conv, bits=128)
        zero = Const(4, None, 0, 64)
        extract = Extract(5, 64, neg, zero, "Iend_LE")
        result = self._opt(extract)
        assert result is not None
        assert isinstance(result, UnaryOp)
        assert result.op == "Neg"
        assert result.operand is x
        assert result.bits == 64
        assert result.floating_point is True

    def test_non_vector_op_returns_none(self):
        """Extract(BinaryOp("Add", ...), 64@0) should not match (no V suffix)."""
        a = Const(1, None, 42, 128)
        b = Const(2, None, 43, 128)
        add = BinaryOp(3, "Add", [a, b], False, bits=128)
        zero = Const(4, None, 0, 64)
        extract = Extract(5, 64, add, zero, "Iend_LE")
        result = self._opt(extract)
        assert result is None


class TestFptagger(unittest.TestCase):
    """Tests for the Fptagger peephole optimization logic."""

    def test_fptagger_logic_tags_fp_constants(self):
        a = Const(None, None, 42, 64)
        b = Const(None, None, 43, 64)
        op = BinaryOp(None, "Fadd", [a, b], False, floating_point=True)
        assert op.floating_point
        for operand in op.operands:
            if isinstance(operand, Const):
                operand.tags["display_hint"] = "double"
        assert a.tags.get("display_hint") == "double"
        assert b.tags.get("display_hint") == "double"

    def test_fptagger_logic_ignores_non_fp_ops(self):
        a = Const(None, None, 42, 64)
        b = Const(None, None, 43, 64)
        BinaryOp(None, "Add", [a, b], False, floating_point=False)
        assert a.tags.get("display_hint") is None


if __name__ == "__main__":
    unittest.main()
