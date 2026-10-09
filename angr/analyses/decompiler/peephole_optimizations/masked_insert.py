from __future__ import annotations

import archinfo

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Extract, Insert, Reinterpret, UnaryOp

from .base import PeepholeOptimizationExprBase


def _insert_shift(expr: Insert) -> int | None:
    """Bit position of the inserted value inside the Insert, counted from the LSB."""
    if not (isinstance(expr.offset, Const) and isinstance(expr.offset.value, int)):
        return None
    if expr.endness == archinfo.Endness.LE:
        shift = expr.offset.value * 8
    else:
        shift = expr.bits - expr.offset.value * 8 - expr.value.bits
    if shift < 0 or shift + expr.value.bits > expr.bits:
        return None
    return shift


def _extract_shift(expr: Extract) -> int | None:
    if not (isinstance(expr.offset, Const) and isinstance(expr.offset.value, int)):
        return None
    if expr.endness == archinfo.Endness.LE:
        shift = expr.offset.value * 8
    else:
        shift = expr.base.bits - expr.offset.value * 8 - expr.bits
    if shift < 0 or shift + expr.bits > expr.base.bits:
        return None
    return shift


def _visibly_fp(expr: Expression) -> bool:
    """An integer Convert would turn this value into a numeric conversion instead of a bit view."""
    if isinstance(expr, Const):
        return isinstance(expr.value, float)
    if isinstance(expr, (BinaryOp, UnaryOp)):
        return expr.floating_point
    if isinstance(expr, Convert):
        return expr.to_type == Convert.TYPE_FP
    if isinstance(expr, Reinterpret):
        return expr.to_type == "F"
    return False


class SimplifyMaskedInsert(PeepholeOptimizationExprBase):
    """
    Reads of an Insert that only see the inserted value or only see the base:

        Insert(base, off, v) & mask  ==>  (Conv(v) << off*8) & mask     when mask only covers v's bits
                                     ==>  base & mask                     when mask covers none of v's bits
        Extract(Insert(base, off, v), ...) and Conv(Insert(base, off, v)) (truncation) likewise.

    Masks of nested ``& c`` chains are combined, e.g. ``Insert(x, 0, b) & 0xffff & 15`` reads only ``b``.
    """

    __slots__ = ()

    NAME = "Simplify masked reads of Insert"
    expr_classes = (BinaryOp, Extract, Convert)

    def optimize(self, expr: BinaryOp | Extract | Convert, **kwargs):
        if isinstance(expr, BinaryOp):
            return self._optimize_and(expr)
        if isinstance(expr, Extract):
            return self._optimize_extract(expr)
        return self._optimize_convert(expr)

    def _optimize_and(self, expr: BinaryOp) -> Expression | None:
        if expr.op != "And" or expr.floating_point or expr.vector_count:
            return None
        mask = (1 << expr.bits) - 1
        inner: Expression = expr
        while (
            isinstance(inner, BinaryOp)
            and inner.op == "And"
            and inner.bits == expr.bits
            and isinstance(inner.operands[1], Const)
            and isinstance(inner.operands[1].value, int)
        ):
            mask &= inner.operands[1].value
            inner = inner.operands[0]
        if not isinstance(inner, Insert) or inner.bits != expr.bits:
            return None
        shift = _insert_shift(inner)
        if shift is None:
            return None
        hole = ((1 << inner.value.bits) - 1) << shift
        if mask & ~hole == 0:
            if _visibly_fp(inner.value):
                return None
            part = inner.value
            if part.bits < expr.bits:
                part = Convert(self.manager.next_atom(), part.bits, expr.bits, False, part, **inner.tags)
            if shift:
                part = BinaryOp(
                    self.manager.next_atom(),
                    "Shl",
                    [part, Const(self.manager.next_atom(), shift, 8)],
                    False,
                    bits=expr.bits,
                    **inner.tags,
                )
        elif mask & hole == 0:
            part = inner.base
        else:
            return None
        return BinaryOp(
            expr.idx,
            "And",
            [part, Const(self.manager.next_atom(), mask, expr.bits)],
            False,
            bits=expr.bits,
            **expr.tags,
        )

    def _optimize_extract(self, expr: Extract) -> Expression | None:
        ins = expr.base
        if not isinstance(ins, Insert):
            return None
        e_shift = _extract_shift(expr)
        i_shift = _insert_shift(ins)
        if e_shift is None or i_shift is None:
            return None
        v_bits = ins.value.bits
        if i_shift <= e_shift and e_shift + expr.bits <= i_shift + v_bits:
            if expr.bits == v_bits:
                return ins.value
            rel = e_shift - i_shift
            if rel % 8:
                return None
            offset = rel // 8 if expr.endness == archinfo.Endness.LE else (v_bits - rel - expr.bits) // 8
            return Extract(
                expr.idx, expr.bits, ins.value, Const(self.manager.next_atom(), offset, 64), expr.endness, **expr.tags
            )
        if e_shift + expr.bits <= i_shift or i_shift + v_bits <= e_shift:
            return Extract(expr.idx, expr.bits, ins.base, expr.offset, expr.endness, **expr.tags)
        return None

    def _optimize_convert(self, expr: Convert) -> Expression | None:
        ins = expr.operand
        if not (
            isinstance(ins, Insert)
            and expr.from_type == Convert.TYPE_INT
            and expr.to_type == Convert.TYPE_INT
            and expr.to_bits < expr.from_bits
        ):
            return None
        i_shift = _insert_shift(ins)
        if i_shift is None:
            return None
        v_bits = ins.value.bits
        if i_shift == 0 and expr.to_bits <= v_bits:
            if ins.base.tags.get("extra_def", False):
                return None
            if expr.to_bits == v_bits:
                return ins.value
            if _visibly_fp(ins.value):
                return None
            return Convert(expr.idx, v_bits, expr.to_bits, expr.is_signed, ins.value, **expr.tags)
        if i_shift >= expr.to_bits:
            return Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, ins.base, **expr.tags)
        return None
