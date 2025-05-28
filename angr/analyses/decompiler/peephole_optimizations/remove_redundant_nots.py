from __future__ import annotations

from angr.ailment.expression import BinaryOp, UnaryOp

from .base import PeepholeOptimizationExprBase


class RemoveRedundantNots(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant Nots"
    expr_classes = (UnaryOp,)  # all expressions are allowed

    def optimize(self, expr: UnaryOp, **kwargs):
        # Not(Not(expr)) ==> expr
        if expr.op == "Not":
            if isinstance(expr.operand, UnaryOp):
                if expr.operand.op == "Not":
                    return expr.operand.operand
            elif isinstance(expr.operand, BinaryOp) and expr.operand.op in BinaryOp.COMPARISON_NEGATION:
                inner = expr.operand
                negated_op = BinaryOp.COMPARISON_NEGATION[expr.operand.op]
                return BinaryOp(
                    inner.idx,
                    negated_op,
                    inner.operands,
                    inner.signed,
                    bits=inner.bits,
                    floating_point=inner.floating_point,
                    rounding_mode=inner.rounding_mode,
                    vector_count=inner.vector_count,
                    vector_size=inner.vector_size,
                    **inner.tags,
                )

        return None
