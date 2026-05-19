# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ShlToMul(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "a << A => a * (2 ** A)"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op == "Shl" and isinstance(expr.operands[1], Const):
            mul_amount = Const(self.manager.next_atom(), None, 2 ** expr.operands[1].value_int, expr.operands[0].bits)
            return BinaryOp(
                expr.idx,
                "Mul",
                [expr.operands[0], mul_amount],
                expr.signed,
                **expr.tags,
            )

        return None
