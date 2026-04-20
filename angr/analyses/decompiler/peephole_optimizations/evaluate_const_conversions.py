from __future__ import annotations

import struct

from angr.ailment.expression import Const, Convert, Extract
from .base import PeepholeOptimizationExprBase


class EvaluateConstConversions(PeepholeOptimizationExprBase):
    """
    If we see a conversion over a constant, simply evaluate it
    """

    DESCRIPTION = "Conv(*, C) => C'"
    expr_classes = (Convert, Extract)

    def optimize(self, expr, *, stmt_idx: int | None = None, block=None, **kwargs):
        if isinstance(expr, Convert):
            inner = expr.operand
            signed = expr.is_signed
            ints = expr.from_type == expr.to_type == Convert.TYPE_INT
        else:
            inner = expr.base
            signed = False
            ints = True

        if isinstance(expr, Convert) and isinstance(inner, Const):
            if isinstance(inner.value, int):
                fp_result = self._try_evaluate_fp_convert(expr, inner)
                if fp_result is not None:
                    return fp_result
            elif isinstance(inner.value, float):
                fp_result = self._try_evaluate_fp_convert_float(expr, inner)
                if fp_result is not None:
                    return fp_result

        if not ints or not isinstance(inner, Const) or not isinstance(inner.value, int):
            return None

        value = inner.value
        value &= (1 << expr.bits) - 1  # disards sign
        if signed and value >= 1 << (expr.bits - 1):
            value -= 1 << expr.bits  # re-adds sign

        return Const(inner.idx, inner.variable, value, expr.bits, **inner.tags)

    @staticmethod
    def _try_evaluate_fp_convert(expr: Convert, inner: Const) -> Const | None:
        """Evaluate FP conversions on integer-encoded float constants.

        Values are kept as integer bit patterns with display_hint="double" so the
        C code generator renders them as floating-point literals.
        """
        from_fp = expr.from_type == Convert.TYPE_FP
        to_fp = expr.to_type == Convert.TYPE_FP

        if from_fp and to_fp:
            # Float->Float widening/narrowing (e.g., 32F->64F, 64F->32F)
            if expr.from_bits == 32 and expr.to_bits == 64:
                bits32 = int(inner.value) & 0xFFFFFFFF
                (f32,) = struct.unpack("<f", struct.pack("<I", bits32))
                (bits64,) = struct.unpack("<Q", struct.pack("<d", f32))
                tags = dict(inner.tags)
                tags["display_hint"] = "double"
                return Const(inner.idx, inner.variable, bits64, 64, **tags)
            if expr.from_bits == 64 and expr.to_bits == 32:
                bits64 = int(inner.value) & 0xFFFFFFFFFFFFFFFF
                (f64,) = struct.unpack("<d", struct.pack("<Q", bits64))
                (bits32,) = struct.unpack("<I", struct.pack("<f", f64))
                return Const(inner.idx, inner.variable, bits32, 32, **inner.tags)

        if not from_fp and to_fp and expr.to_bits == 64:
            # Int->Float (e.g., fild: 32I->s64F)
            value = inner.value
            if expr.is_signed and value >= (1 << (expr.from_bits - 1)):
                value -= 1 << expr.from_bits
            (bits64,) = struct.unpack("<Q", struct.pack("<d", float(value)))
            tags = dict(inner.tags)
            tags["display_hint"] = "double"
            return Const(inner.idx, inner.variable, bits64, 64, **tags)

        return None

    @staticmethod
    def _try_evaluate_fp_convert_float(expr: Convert, inner: Const) -> Const | None:
        """Evaluate FP conversions on constants that already have a Python float value.

        Since the value is already a Python float (double-precision), we just
        produce a new Const with the target bit width -- no bit-pattern encoding
        needed.
        """
        from_fp = expr.from_type == Convert.TYPE_FP
        to_fp = expr.to_type == Convert.TYPE_FP

        if from_fp and to_fp and expr.from_bits != expr.to_bits:
            return Const(inner.idx, inner.variable, inner.value, expr.to_bits, **inner.tags)

        return None
