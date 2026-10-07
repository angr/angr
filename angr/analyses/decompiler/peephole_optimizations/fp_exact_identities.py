from __future__ import annotations

import struct

from angr.ailment.expression import BinaryOp, Const, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase

_ONE_BITS = {32: struct.unpack("<I", struct.pack("<f", 1.0))[0], 64: struct.unpack("<Q", struct.pack("<d", 1.0))[0]}


def _is_fp_one(expr: Expression, bits: int) -> bool:
    if not isinstance(expr, Const) or expr.bits != bits:
        return False
    if isinstance(expr.value, float):
        return expr.value == 1.0
    # an integer constant under an FP operation carries the bit pattern
    return isinstance(expr.value, int) and expr.value == _ONE_BITS.get(bits)


class FPExactIdentities(PeepholeOptimizationExprBase):
    """
    Floating-point simplifications that are value-exact (bit for bit, for every input):

    - ``x * 1.0`` and ``1.0 * x`` -> ``x``: exact for every x, including ±0, ±inf and NaN, in any rounding mode.

    - ``(Exp2(y) - 1.0) + 1.0`` -> ``Exp2(y)``: x87 ``f2xm1; fld1; faddp``. ``Exp2`` comes only from f2xm1, which the
      converter lowers to ``Exp2(y) - 1.0``; f2xm1 is defined only for y in [-1, 1], so e = exp2(y) lies in
      [0.5, 2]. By Sterbenz's lemma e - 1.0 is then exact, and (e - 1.0) + 1.0 = e is representable, so the add is
      exact as well: the folded expression has the same value as the unfolded one in the operation's type. (The
      hardware rounds 2^y - 1 to extended precision before adding 1, so either C form may differ from the machine
      result in the last bit; the fold does not change that.)

    Not folded, since they are not exact: ``(x - 1.0) + 1.0`` for arbitrary x (absorbs tiny x, rounds huge x), and
    ``-(a - b)`` -> ``b - a`` (a == b gives -0.0 vs +0.0).
    """

    __slots__ = ()

    NAME = "Fold value-exact floating-point identities"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if not expr.floating_point or len(expr.operands) != 2:
            return None
        lhs, rhs = expr.operands
        bits = expr.bits

        if expr.op == "Mul":
            if _is_fp_one(rhs, bits) and lhs.bits == bits:
                return lhs
            if _is_fp_one(lhs, bits) and rhs.bits == bits:
                return rhs
            return None

        if expr.op == "Add":
            for one, inner in ((rhs, lhs), (lhs, rhs)):
                if (
                    _is_fp_one(one, bits)
                    and isinstance(inner, BinaryOp)
                    and inner.op == "Sub"
                    and inner.floating_point
                    and inner.bits == bits
                    and _is_fp_one(inner.operands[1], bits)
                    and isinstance(inner.operands[0], UnaryOp)
                    and inner.operands[0].op == "Exp2"
                    and inner.operands[0].bits == bits
                ):
                    return inner.operands[0]
        return None
