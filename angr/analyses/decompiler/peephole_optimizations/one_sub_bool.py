from ailment.expression import Convert, BinaryOp, Const, UnaryOp

from .base import PeepholeOptimizationExprBase


class OneSubBool(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "1 - bool_expr => !bool_expr"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp):
        # Sub(1, Conv(1->N, some bool expression)) ==> Conv(1->N, Not(some bool expression))
        if (
            expr.op == "Sub"
            and isinstance(expr.operands[0], Const)
            and expr.operands[0].value == 1
            and isinstance(expr.operands[1], Convert)
            and expr.operands[1].from_bits == 1
        ):
            conv_expr = expr.operands[1]
            if self.is_bool_expr(conv_expr.operand):
                new_expr = Convert(
                    None,
                    1,
                    conv_expr.to_bits,
                    conv_expr.is_signed,
                    UnaryOp(None, "Not", conv_expr.operand, **conv_expr.operand.tags),
                    **conv_expr.tags,
                )
                return new_expr

        return None
