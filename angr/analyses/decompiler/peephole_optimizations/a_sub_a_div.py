from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ASubADiv(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "a - a / N => a * (N - 1) / N"
    expr_classes = (BinaryOp, )

    def optimize(self, expr: BinaryOp):

        if expr.op == "Sub" and len(expr.operands) == 2 \
                and isinstance(expr.operands[1], BinaryOp) and expr.operands[1].op == "Div" \
                and isinstance(expr.operands[1].operands[1], Const):
            a = expr.operands[0]
            if expr.operands[1].operands[0].likes(a):
                N = expr.operands[1].operands[1].value
                mul = BinaryOp(expr.idx, "Mul",
                               [a,
                                Const(None, None, N - 1, expr.bits)
                                ],
                               False,
                               **expr.tags)
                div = BinaryOp(expr.operands[1].idx, "Div",
                               [mul,
                                Const(None, None, N, expr.bits, **expr.operands[1].tags)
                               ],
                               False,
                               **expr.operands[1].tags)
                return div

        return None
