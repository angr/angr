from ailment.expression import Reinterpret

from .base import PeepholeOptimizationExprBase


class RemoveRedundantReinterprets(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Simplifying nested Reinterpret"
    expr_classes = (Reinterpret, )  # all expressions are allowed

    def optimize(self, expr: Reinterpret):
        if isinstance(expr.operand, Reinterpret):
            inner = expr.operand
            if expr.from_type == inner.to_type and expr.to_type == inner.from_type:
                return inner.operand

        return None
