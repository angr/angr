from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ASubADiv(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "a - a / N => a * (N - 1) / N"
    expr_classes = (BinaryOp, )

    def optimize(self, expr: BinaryOp):

        if expr.op == "Sub" and len(expr.operands) == 2:
            expr0, expr1 = expr.operands
            if isinstance(expr1, BinaryOp) and expr1.op == "Div" \
                    and isinstance(expr1.operands[1], Const):
                a = expr0
                if expr1.operands[0].likes(a):
                    N = expr1.operands[1].value
                    mul = BinaryOp(expr.idx, "Mul",
                                   [a,
                                    Const(None, None, N - 1, expr.bits)
                                    ],
                                   False,
                                   **expr.tags)
                    div = BinaryOp(expr1.idx, "Div",
                                   [mul,
                                    Const(None, None, N, expr.bits, **expr1.tags)
                                   ],
                                   False,
                                   **expr1.tags)
                    return div

        return None
