from __future__ import annotations
from ailment.expression import Convert, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class RemoveCascadingConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove adjacent conversions"
    expr_classes = (Convert,)

    def optimize(self, expr: Convert, **kwargs):
        if isinstance(expr.operand, Convert):
            inner = expr.operand
            if inner.from_bits == expr.to_bits:
                if inner.from_bits < inner.to_bits:
                    # extension -> truncation
                    return inner.operand
                else:
                    # truncation -> extension
                    # we must clear the top truncated bits
                    mask = (1 << inner.to_bits) - 1
                    return BinaryOp(
                        expr.idx,
                        "And",
                        [inner.operand, Const(None, None, mask, inner.operand.bits)],
                        False,
                        **expr.tags,
                    )
            return Convert(expr.idx, inner.from_bits, expr.to_bits, expr.is_signed, inner.operand, **expr.tags)

        return None
