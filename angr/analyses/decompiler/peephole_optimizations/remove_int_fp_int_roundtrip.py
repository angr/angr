from __future__ import annotations

import archinfo

from angr.ailment.expression import Convert

from .base import PeepholeOptimizationExprBase

# number of significand bits (including the implicit bit) of each FP width
_SIGNIFICAND_BITS = {32: 24, 64: 53}


class RemoveIntFPIntRoundTrip(PeepholeOptimizationExprBase):
    """
    Conv(F->sN, Conv(sN->F, x)) ==> x when the int -> FP conversion is exact.

    That is the case when the FP significand holds every N-bit integer, and also for 64-bit integers on 32-bit x86:
    there, I64StoF64 only comes from x87 ``fild`` (SSE cannot convert 64-bit integers outside of 64-bit mode), which
    loads into the 80-bit format whose 64-bit significand holds any int64 (precision control does not apply to
    loads). VEX models the x87 registers as F64 regardless. ``fistp`` of an integral value is exact in every rounding
    mode, so the pair is a plain int64 copy, which compilers use to move 8 bytes at once.
    """

    __slots__ = ()

    NAME = "Remove int -> FP -> int round trips"
    expr_classes = (Convert,)

    def optimize(self, expr: Convert, **kwargs):
        inner = expr.operand
        if not (
            expr.from_type == Convert.TYPE_FP
            and expr.to_type == Convert.TYPE_INT
            and isinstance(inner, Convert)
            and inner.from_type == Convert.TYPE_INT
            and inner.to_type == Convert.TYPE_FP
            and inner.from_bits == expr.to_bits
            and inner.to_bits == expr.from_bits
            and inner.is_signed == expr.is_signed
        ):
            return None
        significand = _SIGNIFICAND_BITS.get(inner.to_bits)
        if significand is None:
            return None
        int_bits = inner.from_bits - 1 if inner.is_signed else inner.from_bits
        if int_bits <= significand:
            return inner.operand
        if (
            inner.from_bits == 64
            and inner.to_bits == 64
            and inner.is_signed
            and self.project is not None
            and isinstance(self.project.arch, archinfo.ArchX86)
        ):
            return inner.operand
        return None
