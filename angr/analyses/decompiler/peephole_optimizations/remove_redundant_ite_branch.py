from __future__ import annotations
from angr.ailment.expression import ITE, BinaryOp

from .base import PeepholeOptimizationExprBase


class RemoveRedundantITEBranches(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant ITE branches"
    expr_classes = (ITE,)

    def optimize(self, expr: ITE, **kwargs):
        # ITE(cond, a, ITE(!cond, b, c)) ==> ITE(cond, a, b)
        if (
            isinstance(expr.iffalse, ITE)
            # cascading ITEs
            and isinstance(expr.cond, BinaryOp)
            # are they negating each other?
            and isinstance(expr.iffalse.cond, BinaryOp)
            and expr.cond.op in BinaryOp.COMPARISON_NEGATION
            and expr.iffalse.cond.op == BinaryOp.COMPARISON_NEGATION[expr.cond.op]
        ):
            cond0_operands = expr.cond.operands
            cond1_operands = expr.iffalse.cond.operands
            if cond0_operands[0].likes(cond1_operands[0]) and cond0_operands[1].likes(cond1_operands[1]):
                # YES...
                return ITE(expr.idx, expr.cond, expr.iffalse.iftrue, expr.iftrue, **expr.tags)

        return None
