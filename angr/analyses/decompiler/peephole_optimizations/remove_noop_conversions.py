# pylint: disable=missing-class-docstring
from ailment.expression import Convert

from .base import PeepholeOptimizationExprBase


class RemoveNoopConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove no-op conversions"
    expr_classes = (Convert,)

    def optimize(self, expr: Convert):
        if expr.from_bits == expr.to_bits:
            return expr.operand

        return None
