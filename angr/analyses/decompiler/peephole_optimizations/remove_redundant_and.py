from __future__ import annotations

from angr.ailment.expression import BinaryOp, Call, DirtyExpression, Expression

from .base import PeepholeOptimizationExprBase


def _evaluates_twice_safely(expr: Expression, depth: int = 0) -> bool:
    """Whether dropping one of two identical evaluations of ``expr`` is observationally silent."""
    if depth > 8:
        return False
    if isinstance(expr, (Call, DirtyExpression)):
        return False
    return all(_evaluates_twice_safely(operand, depth + 1) for operand in getattr(expr, "operands", None) or ())


class RemoveRedundantAnds(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant Ands"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        # And(a,a) => a
        if expr.op == "And" and expr.operands[0].likes(expr.operands[1]):
            # likes() ignores idx, so the two operands may be distinct evaluations. Folding them
            # is only silent when evaluating once instead of twice cannot be observed -- a call
            # or a dirty helper appearing twice really does run twice.
            if not _evaluates_twice_safely(expr.operands[0]):
                return None
            return expr.operands[0]
        return None
