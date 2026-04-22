from __future__ import annotations

import math

from angr.ailment.expression import Const, ITE

from .base import PeepholeOptimizationExprBase


class RemoveFptagNanITE(PeepholeOptimizationExprBase):
    """
    VEX x87 lifting wraps FP register accesses in fptag validity checks:
      ITE(fptag != 0, fp_value, NaN)   -- for reads (valid -> value, empty -> NaN)
      ITE(fptag != 0, NaN, fp_value)   -- for pushes (in-use -> overflow NaN, empty -> value)

    Since decompiled code assumes FP registers are valid, strip these ITEs and
    keep the non-NaN branch.
    """

    __slots__ = ()

    NAME = "Remove fptag NaN ITE checks"
    expr_classes = (ITE,)

    def optimize(self, expr: ITE, **kwargs):
        iftrue_is_nan = (
            isinstance(expr.iftrue, Const) and isinstance(expr.iftrue.value, float) and math.isnan(expr.iftrue.value)
        )
        iffalse_is_nan = (
            isinstance(expr.iffalse, Const) and isinstance(expr.iffalse.value, float) and math.isnan(expr.iffalse.value)
        )

        if iftrue_is_nan and not iffalse_is_nan:
            return expr.iffalse
        if iffalse_is_nan and not iftrue_is_nan:
            return expr.iftrue
        if iftrue_is_nan and iffalse_is_nan:
            # Both branches are NaN -- just return NaN constant
            return expr.iftrue

        return None
