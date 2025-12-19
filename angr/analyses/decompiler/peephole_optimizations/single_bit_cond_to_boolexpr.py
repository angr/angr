from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const, UnaryOp

from .base import PeepholeOptimizationExprBase


class SingleBitCondToBoolExpr(PeepholeOptimizationExprBase):
    """
    Convert single-bit conditions to bool expressions
    """

    __slots__ = ()

    NAME = "Convert single-bit conditions to bool expressions (== 0 or == 1)"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.bits != 1:
            return None

        if expr.op == "Xor" and isinstance(expr.operands[1], Const) and expr.operands[1].value == 1:
            return UnaryOp(None, "Not", expr.operands[0], **expr.tags)
        if expr.op in ("CmpEQ", "CmpNE") and isinstance(expr.operands[1], Const) and expr.operands[0].bits == 1:
            if (expr.operands[1].value == 0) ^ (expr.op == "CmpEQ"):
                return expr.operands[0]
            return UnaryOp(None, "Not", expr.operands[0], **expr.tags)

        return None
