# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations
from angr.ailment.expression import BinaryOp, Convert, Insert, Const

from .base import PeepholeOptimizationExprBase


class RemoveConstInsert(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Insert(c0, c1, v) ==> (c0 & mask) | (v << c1)"
    expr_classes = (Insert,)

    def optimize(self, expr: Insert, **kwargs):
        if not (
            isinstance(expr.base, Const)
            and isinstance(expr.base.value, int)
            and isinstance(expr.offset, Const)
            and isinstance(expr.offset.value, int)
        ):
            return None

        # TODO fix big-endian?
        assert self.project is not None
        base = expr.base.value & ~((1 << expr.value.bits) - 1) << (expr.offset.value * self.project.arch.byte_width)
        value = Convert(None, expr.value.bits, expr.bits, False, expr.value)
        shifted = (
            BinaryOp(
                None,
                "Shl",
                [value, Const(None, None, expr.offset.value * self.project.arch.byte_width, expr.bits)],
                signed=False,
            )
            if expr.offset.value != 0
            else value
        )
        return BinaryOp(expr.idx, "Or", [shifted, Const(None, None, base, shifted.bits)], signed=False)
