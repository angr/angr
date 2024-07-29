# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations
from ailment.expression import Convert

from .base import PeepholeOptimizationExprBase


class RemoveNoopConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove no-op conversions"
    expr_classes = (Convert,)

    def optimize(self, expr: Convert, **kwargs):
        if expr.from_bits == expr.to_bits:
            return expr.operand

        if isinstance(expr.operand, Convert):
            inner = expr.operand
            if (
                expr.to_bits == inner.from_bits
                and expr.to_bits < expr.from_bits
                and expr.from_bits == inner.to_bits
                and expr.is_signed == inner.is_signed
            ):
                # extension then truncation (e.g., 1->64->1) can be removed, but truncation then extension cannot be
                # removed (e.g., the high 32 bits must be removed during 64->32->64)
                return inner.operand

        return None
