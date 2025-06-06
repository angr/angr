# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class AShlConstSubA(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "(a << N) - a => (a * (2 ** N - 1))"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if (
            expr.op == "Sub"
            and len(expr.operands) == 2
            and isinstance(expr.operands[0], BinaryOp)
            and expr.operands[0].op == "Shl"
            and isinstance(expr.operands[0].operands[1], Const)
            and expr.signed == expr.operands[0].signed
        ):
            a = expr.operands[1]
            if expr.operands[0].operands[0].likes(a):
                N = expr.operands[0].operands[1].value
                return BinaryOp(
                    expr.idx,
                    "Mul",
                    [a, Const(None, None, 2**N - 1, expr.bits, **expr.operands[0].operands[1].tags)],
                    expr.signed,
                    **expr.tags,
                )

        return None
