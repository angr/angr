# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

from archinfo import Endness

from angr.ailment.expression import BinaryOp, Const, Convert, Insert, VirtualVariable

from .base import PeepholeOptimizationExprBase


class LowerInsert(PeepholeOptimizationExprBase):
    """
    Lower any remaining Insert into mask-and-or arithmetic.

    This is a lowering rule, not a simplification: it is meant to run once, after all other peephole optimizations
    have reached a fixed point, so that the prettier rewrites (RemoveRedundantInsert, RemoveConstInsert,
    SimplifyBitwiseInserts, RemoveRedundantBitmasks) still get the first shot at every Insert. Whatever survives them
    would otherwise reach the C backend and be rendered as a call to the non-existent function `_INSERT`.
    """

    __slots__ = ()

    NAME = "Insert(b, c, v) ==> (b & mask) | (v << c)"
    expr_classes = (Insert,)

    def optimize(self, expr: Insert, **kwargs):
        if not (isinstance(expr.offset, Const) and isinstance(expr.offset.value, int)):
            return None

        assert self.project is not None
        # TODO support big-endian, like the other Insert optimizers
        if self.project.arch.memory_endness is not Endness.LE:
            return None

        # partial stores into stack variables are rendered by the C backend as `*((char *)&v + offset) = value`, which
        # is far more readable than mask-and-or arithmetic. leave them alone.
        if isinstance(expr.base, VirtualVariable) and expr.base.was_stack:
            return None
        # an uninitialized base means the surrounding bits are undefined; the C backend has a dedicated rendering for
        # this case as well.
        if expr.base.tags.get("uninitialized", False):
            return None

        shift = expr.offset.value * self.project.arch.byte_width
        if expr.value.bits + shift > expr.bits:
            # malformed Insert - the value does not fit into the base
            return None
        # only lower Inserts that fit in a machine word: wider ones come from bulk memory operations and would only
        # yield arithmetic on integer types that do not exist in C.
        if expr.bits > self.project.arch.bits:
            return None
        # if the base is a widening Convert and the insert reaches beyond the converted operand's width, the bits this
        # Insert claims to preserve are extension padding rather than data the base genuinely carries. In practice
        # this shape appears when an earlier pass has over-narrowed the base of a sub-register write, and lowering it
        # would bake that loss into plausible-looking arithmetic. Bail and leave the Insert visible instead.
        if (
            isinstance(expr.base, Convert)
            and expr.base.from_bits < expr.base.to_bits
            and shift + expr.value.bits > expr.base.from_bits
        ):
            return None

        value = (
            expr.value
            if expr.value.bits == expr.bits
            else Convert(self.manager.next_atom(), expr.value.bits, expr.bits, False, expr.value)
        )
        shifted = (
            BinaryOp(
                self.manager.next_atom(),
                "Shl",
                [value, Const(self.manager.next_atom(), shift, expr.bits)],
                signed=False,
            )
            if shift
            else value
        )

        keep = ~(((1 << expr.value.bits) - 1) << shift) & ((1 << expr.bits) - 1)
        if keep == 0:
            # the value overwrites the base in its entirety
            return shifted

        if isinstance(expr.base, Const) and isinstance(expr.base.value, int):
            masked_base = Const(self.manager.next_atom(), expr.base.value & keep, expr.bits)
        else:
            masked_base = BinaryOp(
                self.manager.next_atom(),
                "And",
                [expr.base, Const(self.manager.next_atom(), keep, expr.bits)],
                signed=False,
            )

        return BinaryOp(expr.idx, "Or", [masked_base, shifted], signed=False, **expr.tags)
