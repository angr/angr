from ailment.expression import Convert

from .base import PeepholeOptimizationExprBase


class RemoveCascadingConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove adjacent conversions"
    expr_classes = (Convert, )

    def optimize(self, expr: Convert):

        if isinstance(expr.operand, Convert):
            inner = expr.operand
            if inner.from_bits == expr.to_bits:
                return inner.operand
            return Convert(expr.idx, inner.from_bits, expr.to_bits, expr.is_signed, inner.operand,
                           **expr.tags)

        return None
