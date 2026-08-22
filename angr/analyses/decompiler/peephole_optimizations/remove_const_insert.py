# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

from archinfo import Endness

from angr.ailment.expression import BinaryOp, Const, Convert, Insert

from .base import PeepholeOptimizationExprBase


class RemoveConstInsert(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Insert(c0, c1, v) ==> (c0 & mask) | (v << c1)"
    expr_classes = (Insert,)

    def optimize(self, expr: Insert, **kwargs):
        if not (
            isinstance(expr.base, Const)
            and not expr.base.tags.get("uninitialized", False)
            and isinstance(expr.base.value, int)
            and isinstance(expr.offset, Const)
            and isinstance(expr.offset.value, int)
        ):
            return None

        assert self.project is not None
        if expr.endness == Endness.LE:
            shift = expr.offset.value * self.project.arch.byte_width
        elif expr.endness == Endness.BE:
            shift = expr.base.bits - expr.value.bits - expr.offset.value * self.project.arch.byte_width
        else:
            return None
        if shift < 0 or shift + expr.value.bits > expr.base.bits:
            return None

        inserted_mask = ((1 << expr.value.bits) - 1) << shift
        base = expr.base.value & ((1 << expr.base.bits) - 1) & ~inserted_mask
        value = Convert(self.manager.next_atom(), expr.value.bits, expr.bits, False, expr.value)
        shifted = (
            BinaryOp(
                self.manager.next_atom(),
                "Shl",
                [
                    value,
                    Const(self.manager.next_atom(), shift, expr.bits),
                ],
                signed=False,
            )
            if shift != 0
            else value
        )
        return BinaryOp(expr.idx, "Or", [shifted, Const(self.manager.next_atom(), base, shifted.bits)], signed=False)
