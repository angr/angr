from ailment.expression import BinaryOp, Const, UnaryOp, Convert

import ailment.ailment.expression
from .base import PeepholeOptimizationExprBase


class XorSimplifications(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "expr 2 ^ expr1 ^ expr1 => expr2"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp):
        if expr.op == "Xor" and isinstance(expr.operands[0], BinaryOp) and expr.operands[0].op == "Xor":
            if expr.operands[1].likes(expr.operands[0].operands[1]):
                return expr.operands[0].operands[0]
        return None
