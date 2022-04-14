from ailment.expression import BinaryOp, Const, UnaryOp, Convert

from .base import PeepholeOptimizationExprBase


class BoolExprXor1(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "bool_expr ^ 1 => !bool_expr (a)"
    expr_classes = (BinaryOp, )  # all expressions are allowed

    def optimize(self, expr: BinaryOp):

        # Conv(1->N, some_bool_expr) ^ 1 ==> Conv(1->N, Not(some_bool_expr))
        if expr.op == "Xor" and isinstance(expr.operands[1], Const) and expr.operands[1].value == 1:
            arg0 = expr.operands[0]
            if isinstance(arg0, Convert) and arg0.from_bits == 1 \
                    and self.is_bool_expr(arg0.operand):
                new_expr = Convert(None, 1, arg0.to_bits, arg0.is_signed,
                                   UnaryOp(None, 'Not', arg0.operands[0], **expr.tags),
                                   **arg0.tags)
                return new_expr

        return None
