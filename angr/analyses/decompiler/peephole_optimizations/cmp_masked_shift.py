from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class CmpMaskedShift(PeepholeOptimizationExprBase):
    """
    Rewrite an equality comparison against a right-shifted value back into a
    masked comparison, which reads better for flag/discriminant checks.

        (x >> n) == c                   ==>  (x & mask) == (c << n)
        Convert(N->M, x >> n) == c      ==>  (x & mask) == (c << n)

    where ``mask`` selects the compared bits ``[n, n+width-1]`` of ``x`` and
    ``width`` is the truncated width ``M`` (or ``N - n`` when there is no
    Convert). This is the inverse of a simplification that can turn
    ``(x & high_mask) == c`` (a mask that clears the low bits) into the
    shift/extract form: the masked compare is the clearer form in decompiled
    output, so restore it.

    Only logical right shifts and unsigned truncations are handled, and only
    ``n > 0`` (a low-mask compare, ``n == 0``, already reads as a cast).
    """

    __slots__ = ()

    NAME = "(x >> n) == c => (x & mask) == (c << n)"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in ("CmpEQ", "CmpNE"):
            return None

        op0, op1 = expr.operands
        # Normalize so the constant is op1.
        if isinstance(op0, Const) and not isinstance(op1, Const):
            op0, op1 = op1, op0
        if not isinstance(op1, Const) or not op1.is_int:
            return None

        # Peel an optional unsigned truncating Convert.
        shifted = op0
        width = None
        if isinstance(shifted, Convert):
            if shifted.is_signed or shifted.to_bits >= shifted.from_bits:
                return None
            width = shifted.to_bits
            shifted = shifted.operand

        # The inner expression must be a logical right shift by a constant.
        if not (isinstance(shifted, BinaryOp) and shifted.op == "Shr"):
            return None
        x, shift = shifted.operands
        if not (isinstance(shift, Const) and shift.is_int):
            return None
        n = shift.value_int
        if n <= 0:
            return None

        bits = x.bits
        if width is None:
            width = bits - n
        if width <= 0 or n + width > bits:
            return None

        c = op1.value_int
        if c >> width != 0:
            # The constant does not fit in the compared width; not this pattern.
            return None

        mask = ((1 << width) - 1) << n
        new_const = c << n

        and_expr = BinaryOp(
            self.manager.next_atom(),
            "And",
            (
                x,
                Const(self.manager.next_atom(), mask, bits),
            ),
            False,
            **expr.tags,
        )
        return BinaryOp(
            expr.idx,
            expr.op,
            (
                and_expr,
                Const(self.manager.next_atom(), new_const, bits),
            ),
            expr.signed,
            bits=expr.bits,
            floating_point=expr.floating_point,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )
