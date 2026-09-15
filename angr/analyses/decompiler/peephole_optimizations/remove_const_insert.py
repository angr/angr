# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Insert
from angr.ailment.utils import lsb_bit_offset

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
        shift = lsb_bit_offset(
            expr.bits, expr.value.bits, expr.offset.value, expr.endness, self.project.arch.byte_width
        )
        base = expr.base.value & ~(((1 << expr.value.bits) - 1) << shift)
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
