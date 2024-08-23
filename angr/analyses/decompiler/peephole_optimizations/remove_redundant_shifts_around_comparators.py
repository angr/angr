from __future__ import annotations
from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantShiftsAroundComparators(PeepholeOptimizationExprBase):
    """
    Remove redundant bitshifts for both operands around a comparison operator.

    More cases can be added in the future as we encounter them.
    """

    __slots__ = ()

    NAME = "Remove redundant bitshifts for operands around a comparator"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        # (expr_0 << N) < (expr_1 << N)  ==> expr_0 << expr_1
        # FIXME: This optimization is unsafe but seems to work for all existing case
        if expr.op in {"CmpLE", "CmpLT", "CmpEQ", "CmpNE", "CmpGE", "CmpGT"}:
            op0, op1 = expr.operands
            if (
                isinstance(op0, BinaryOp)
                and op0.op == "Shl"
                and isinstance(op1, BinaryOp)
                and op1.op == "Shl"
                and isinstance(op0.operands[1], Const)
                and isinstance(op1.operands[1], Const)
                and op0.operands[1].value == op1.operands[1].value
            ):
                return BinaryOp(
                    expr.idx,
                    expr.op,
                    [op0.operands[0], op1.operands[0]],
                    expr.signed,
                    bits=expr.bits,
                    floating_point=expr.floating_point,
                    rounding_mode=expr.rounding_mode,
                    **expr.tags,
                )

        return None
