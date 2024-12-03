# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations
from ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase
from .utils import get_expr_shift_left_amount


class RemoveRedundantShifts(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant bitshifts"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        # (expr << N) >> N  ==> Convert((M-N)->M, Convert(M->(M-N), expr))
        if expr.op in ("Shr", "Sar") and isinstance(expr.operands[1], Const):
            expr_a = expr.operands[0]
            n0 = expr.operands[1].value
            if isinstance(expr_a, BinaryOp) and expr_a.op in {"Shl", "Mul"} and isinstance(expr_a.operands[1], Const):
                n1 = get_expr_shift_left_amount(expr_a)
                if n0 == n1:
                    inner_expr = expr_a.operands[0]
                    conv_inner_expr = Convert(
                        None,
                        expr_a.bits,
                        expr_a.bits - n0,
                        expr.op == "Sar",  # is_signed
                        inner_expr,
                        **expr.tags,
                    )
                    return Convert(
                        None,
                        expr_a.bits - n0,
                        expr.bits,
                        False,
                        conv_inner_expr,
                        **expr.tags,
                    )

        # expr << 0  ==>  expr
        # expr >> 0  ==>  expr
        if expr.op in {"Shl", "Shr", "Sar"} and isinstance(expr.operands[1], Const) and expr.operands[1].value == 0:
            return expr.operands[0]

        return None
