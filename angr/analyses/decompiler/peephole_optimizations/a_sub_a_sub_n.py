from ailment.expression import BinaryOp

from .base import PeepholeOptimizationExprBase


class ASubASubN(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "expr - (expr - N) => N"
    expr_classes = (BinaryOp, )  # all expressions are allowed

    def optimize(self, expr: BinaryOp):

        # Sub(A, Sub(A, N)) ==> N
        if expr.op == "Sub" and isinstance(expr.operands[1], BinaryOp) and expr.operands[1].op == "Sub":
            if expr.operands[0] == expr.operands[1].operands[0]:
                new_expr = expr.operands[1].operands[1]
                return new_expr

        return None
