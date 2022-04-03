from ailment.expression import UnaryOp

from .base import PeepholeOptimizationExprBase


class RemoveRedundantNots(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant Nots"
    expr_classes = (UnaryOp, )  # all expressions are allowed

    def optimize(self, expr: UnaryOp):

        # Not(Not(expr)) ==> expr
        if expr.op == "Not" \
                and isinstance(expr.operand, UnaryOp) \
                and expr.operand.op == "Not":
            return expr.operand.operand

        return None
