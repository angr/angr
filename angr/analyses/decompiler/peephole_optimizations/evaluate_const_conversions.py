from __future__ import annotations
from angr.ailment.expression import Const, Convert, Extract
from .base import PeepholeOptimizationExprBase


class EvaluateConstConversions(PeepholeOptimizationExprBase):
    DESCRIPTION = "Conv(*, C) => C'"
    expr_classes = (Convert, Extract)

    def optimize(self, expr, *, stmt_idx: int | None = None, block=None, **kwargs):
        if isinstance(expr, Convert):
            inner = expr.operand
            signed = expr.is_signed
            ints = expr.from_type == expr.to_type == Convert.TYPE_INT
        else:
            inner = expr.base
            signed = False
            ints = True
        if not ints or not isinstance(inner, Const) or not isinstance(inner.value, int):
            return None

        value = inner.value
        value &= (1 << expr.bits) - 1  # disards sign
        if signed and value >= 1 << (expr.bits - 1):
            value -= 1 << expr.bits  # re-adds sign

        return Const(inner.idx, inner.variable, value, expr.bits, **inner.tags)
