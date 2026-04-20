# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class Fptagger(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Tag constants used in floating point ops for display"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.floating_point:
            for operand in expr.operands:
                if isinstance(operand, Const):
                    operand.tags["display_hint"] = "double"
