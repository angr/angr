from ailment.expression import Convert, BinaryOp, Const, UnaryOp

from .base import PeepholeOptimizationExprBase


class SingleBitXor(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "bool_expr ^ 1 => !bool_expr (b)"
    expr_classes = (Convert, )  # all expressions are allowed

    def optimize(self, expr: Convert):

        # Convert(N->1, (Convert(1->N, t_x) ^ 0x1<N>) ==> Not(t_x)
        if expr.to_bits == 1:
            xor_expr = expr.operand
            if isinstance(xor_expr, BinaryOp) and xor_expr.op == "Xor":
                if isinstance(xor_expr.operands[0], Convert) and \
                        isinstance(xor_expr.operands[1], Const) and \
                        xor_expr.operands[1].value == 1 and \
                        xor_expr.operands[0].from_bits == 1:
                    new_expr = UnaryOp(None, "Not", expr.operand.operands[0].operand)
                    return new_expr

        return expr
