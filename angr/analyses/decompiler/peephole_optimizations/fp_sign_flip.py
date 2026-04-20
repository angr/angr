"""Simplify FP sign-bit XOR to negation.

Floating-point negation is often compiled as ``x ^ sign_bit_mask`` using
vector XOR instructions.  In AIL this appears as a 128-bit
``x ^ 0x8000...``.  This peephole replaces it with
``UnaryOp("Neg", x, floating_point=True)`` so codegen renders ``-x``.

Only matches 128-bit XOR to avoid false positives on integer code that
happens to XOR with the same constant (e.g. ``x ^ INT_MIN``).
"""

from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, UnaryOp, Convert, Extract

from .base import PeepholeOptimizationExprBase

# Sign-bit masks for each scalar FP width inside a 128-bit vector register.
_FP_SIGN_MASKS = {
    0x80000000,  # float  (32-bit sign bit)
    0x8000000000000000,  # double (64-bit sign bit)
    0x80000000000000000000000000000000,  # full 128-bit
}


class FPSignFlipToNeg(PeepholeOptimizationExprBase):
    """Replace x ^ sign_bit_mask with -x for floating-point values."""

    __slots__ = ()

    NAME = "FP sign bit XOR to negation"
    expr_classes = (BinaryOp, Extract)

    def optimize(self, expr: BinaryOp | Extract, **kwargs):
        # Pattern 1: Extract(Conv(64->128, x) ^ 0x8000...<128>, 64@0)
        if isinstance(expr, Extract) and expr.is_lsb_extract():
            inner = expr.base
            operand = self._match_vector_xor_sign(inner)
            if operand is not None:
                # Unwrap Conv if present
                if isinstance(operand, Convert) and operand.to_bits > operand.from_bits:
                    operand = operand.operand
                if operand.bits == expr.bits:
                    return UnaryOp(expr.idx, "Neg", operand, floating_point=True, **expr.tags)

        # Pattern 2: 128-bit XOR with sign mask (vector register op)
        if isinstance(expr, BinaryOp):
            operand = self._match_vector_xor_sign(expr)
            if operand is not None:
                return UnaryOp(expr.idx, "Neg", operand, floating_point=True, **expr.tags)

        return None

    @staticmethod
    def _match_vector_xor_sign(expr):
        """Match a 128-bit ``x ^ sign_bit_mask``.  Returns x if matched, else None.

        Only matches 128-bit XOR (vector register width) to distinguish FP
        sign flips from integer operations.  Accepts the 32-bit, 64-bit, or
        128-bit sign mask inside the 128-bit field.
        """
        if not isinstance(expr, BinaryOp) or expr.op != "Xor" or expr.bits != 128:
            return None

        lhs, rhs = expr.operands
        if isinstance(rhs, Const) and rhs.value in _FP_SIGN_MASKS:
            return lhs
        if isinstance(lhs, Const) and lhs.value in _FP_SIGN_MASKS:
            return rhs
        return None
