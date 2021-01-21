from ailment.expression import Convert, BinaryOp, Const, UnaryOp

from .base import PeepholeOptimizationExprBase


class SingleBitXor(PeepholeOptimizationExprBase):
    __slots__ = ()

    expr_classes = (Convert, )  # all expressions are allowed

    def optimize(self, expr: Convert):

        # Convert(N->1, (Convert(1->N, t_x) ^ 0x1<N>) ==> Not(t_x)
        if isinstance(expr.operand, BinaryOp) and \
                expr.operand.op == "Xor" and \
                isinstance(expr.operand.operands[0], Convert) and \
                isinstance(expr.operand.operands[1], Const) and \
                expr.operand.operands[1].value == 1:
            new_expr = UnaryOp(None, "Not", expr.operand.operands[0].operand)
            return new_expr

        return expr
