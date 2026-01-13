# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations
from angr.ailment.expression import Convert, Extract

from .base import PeepholeOptimizationExprBase


class RemoveNoopConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove no-op conversions"
    expr_classes = (Convert, Extract)

    def optimize(self, expr: Convert | Extract, **kwargs):
        if isinstance(expr, Convert):
            inner = expr.operand
            signed = expr.is_signed
            ints = expr.from_type == expr.to_type == Convert.TYPE_INT
        else:
            inner = expr.base
            signed = False
            ints = True

        if inner.bits == expr.bits and ints:
            return inner

        if isinstance(inner, Convert):
            if (
                expr.bits < inner.bits
                and expr.bits == inner.operand.bits
                and ints
                and inner.from_type == inner.to_type == Convert.TYPE_INT
            ):
                # extension then truncation (e.g., 1->64->1) can be removed, but truncation then extension cannot be
                # removed (e.g., the high 32 bits must be removed during 64->32->64)
                return inner.operand
            if (
                expr.bits < inner.from_bits
                and inner.to_bits >= inner.from_bits
                and ints
                and inner.from_type == inner.to_type == Convert.TYPE_INT
            ):
                # merging two truncations into one
                return Convert(
                    expr.idx,
                    inner.from_bits,
                    expr.bits,
                    signed,
                    inner.operand,
                    **expr.tags,
                )

        return None
