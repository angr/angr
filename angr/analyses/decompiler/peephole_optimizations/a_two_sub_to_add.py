from ailment.expression import BinaryOp, UnaryOp, Const

from .base import PeepholeOptimizationExprBase


class TwoSubToAdd(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "expr - - N => expr + N"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op == "Sub" and isinstance(expr.operands[1], Const) and expr.operands[1].value < 0:
            return BinaryOp(
                    expr.idx,
                    "Add",
                    [expr.operands[0], Const(None, None, -expr.operands[1].value, expr.operands[1].bits, **expr.operands[1].tags)],
                    expr.signed,
                    **expr.tags,
                )


        return None
