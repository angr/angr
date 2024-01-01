from ailment.expression import BinaryOp

from .base import PeepholeOptimizationExprBase


class RemoveRedundantAnds(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant Ands"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        # And(a,a) => a
        if expr.op == "And" and expr.operands[0].likes(expr.operands[1]):
            return expr.operands[0]
        return None
