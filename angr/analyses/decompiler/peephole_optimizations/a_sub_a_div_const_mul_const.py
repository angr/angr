from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ASubADivConstMulConst(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "a - (a / N) * N => a % N"
    expr_classes = (BinaryOp, )

    def optimize(self, expr: BinaryOp):

        if expr.op == "Sub" and len(expr.operands) == 2 \
                and isinstance(expr.operands[1], BinaryOp) and expr.operands[1].op == "Mul" \
                and isinstance(expr.operands[1].operands[1], Const):
            a0 = expr.operands[0]
            op1 = expr.operands[1]
            mul_const = expr.operands[1].operands[1]
            if isinstance(op1.operands[0], BinaryOp) and op1.operands[0].op == "Div" and \
                    isinstance(op1.operands[0].operands[1], Const):
                a1 = op1.operands[0].operands[0]
                div_const = op1.operands[0].operands[1]

                if a0.likes(a1) and mul_const.value == div_const.value:
                    mod = BinaryOp(expr.idx, "DivMod",
                                   [a0,
                                    div_const
                                   ],
                                   False,
                                   **expr.tags)
                    return mod

        return None
