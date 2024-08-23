from __future__ import annotations
from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class AMulConstDivShrConst(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "(A * N0 / N1) >> N2 => (A * (N0 / 2 ** N2) / N1)"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if (
            expr.op == "Shr"
            and len(expr.operands) == 2
            and isinstance(expr.operands[1], Const)
            and isinstance(expr.operands[0], BinaryOp)
            and expr.operands[0].op == "Div"
            and isinstance(expr.operands[0].operands[1], Const)
        ):
            inner = expr.operands[0].operands[0]
            if isinstance(inner, BinaryOp) and inner.op == "Mul" and isinstance(inner.operands[1], Const):
                a = inner.operands[0]
                N0 = inner.operands[1].value
                N1 = expr.operands[0].operands[1]
                N2 = expr.operands[1].value

                mul = BinaryOp(
                    inner.idx,
                    "Mul",
                    [a, Const(None, None, N0 // (2**N2), expr.bits, **expr.operands[0].operands[1].tags)],
                    False,
                    **inner.tags,
                )
                return BinaryOp(expr.idx, "Div", [mul, N1], False, **expr.tags)

        return None
