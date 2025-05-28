# pylint:disable=no-self-use,too-many-boolean-expressions
from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ASubAShrConstShrConst(PeepholeOptimizationExprBase):
    """
    Convert `cdq; sub eax, edx; sar eax, 1` to `eax /= 2`.
    """

    __slots__ = ()

    NAME = "(a - (a >> 31)) >> N => a / 2 ** N (signed)"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if (
            expr.op == "Sar"
            and len(expr.operands) == 2
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].is_int
            and isinstance(expr.operands[0], BinaryOp)
            and expr.operands[0].op == "Sub"
        ):
            a0, a1 = expr.operands[0].operands
            if (
                isinstance(a1, BinaryOp)
                and a1.op == "Sar"
                and isinstance(a1.operands[1], Const)
                and a1.operands[1].value == 31
                and a0.likes(a1.operands[0])
            ):
                dividend = 2 ** expr.operands[1].value
                return BinaryOp(a0.idx, "Div", [a0, Const(None, None, dividend, expr.bits)], True, **expr.tags)
        return None
