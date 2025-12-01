from __future__ import annotations
from angr.ailment.expression import Load, UnaryOp

from .base import PeepholeOptimizationExprBase


class RemoveRedundantDerefs(PeepholeOptimizationExprBase):
    """
    Remove redundant dereferences (e.g. *(&v))
    """

    __slots__ = ()

    NAME = "Remove redundant dereferences"
    expr_classes = (Load,)

    def optimize(self, expr: Load, **kwargs):
        if isinstance(expr.addr, UnaryOp) and expr.addr.op == "Reference" and expr.bits == expr.addr.operand.bits:
            # *(&v) ==> v
            return expr.addr.operand
        return None
