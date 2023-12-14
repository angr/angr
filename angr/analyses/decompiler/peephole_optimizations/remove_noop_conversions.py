# pylint: disable=missing-class-docstring,no-self-use
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
                and expr.from_bits == inner.to_bits
                and expr.is_signed == inner.is_signed
            ):
                return inner.operand

        return None
