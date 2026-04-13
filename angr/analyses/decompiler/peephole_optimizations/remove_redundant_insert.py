# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations
from angr.ailment.expression import Insert, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantInsert(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant INSERT operators"
    expr_classes = (Insert,)

    def optimize(self, expr: Insert, **kwargs):
        if isinstance(expr.offset, Const) and expr.offset.value == 0 and expr.base.bits == expr.value.bits:
            return expr.value

        return None
