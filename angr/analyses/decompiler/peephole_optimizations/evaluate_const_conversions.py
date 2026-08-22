from __future__ import annotations

from archinfo import Endness

from angr.ailment.expression import Const, Convert, Extract

from .base import PeepholeOptimizationExprBase
from .utils import evaluate_const_int_conversion


class EvaluateConstConversions(PeepholeOptimizationExprBase):
    """
    If we see a conversion over a constant, simply evaluate it
    """

    DESCRIPTION = "Conv(*, C) => C'"
    expr_classes = (Convert, Extract)

    def optimize(self, expr, *, stmt_idx: int | None = None, block=None, **kwargs):
        if isinstance(expr, Convert):
            inner = expr.operand
            value = evaluate_const_int_conversion(expr)
            if value is None:
                return None
            return Const(inner.idx, value, expr.bits, **inner.tags)

        inner = expr.base
        if (
            not isinstance(inner, Const)
            or not isinstance(inner.value, int)
            or not isinstance(expr.offset, Const)
            or not isinstance(expr.offset.value, int)
        ):
            return None

        arch = self.project.arch if self.project is not None else getattr(self.manager, "arch", None)
        if arch is None:
            return None
        if expr.endness == Endness.LE:
            shift = expr.offset.value * arch.byte_width
        elif expr.endness == Endness.BE:
            shift = inner.bits - expr.bits - expr.offset.value * arch.byte_width
        else:
            return None
        if shift < 0 or shift + expr.bits > inner.bits:
            return None

        value = (inner.value & ((1 << inner.bits) - 1)) >> shift
        value &= (1 << expr.bits) - 1
        return Const(inner.idx, value, expr.bits, **inner.tags)
