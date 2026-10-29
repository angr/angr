from __future__ import annotations

from angr.ailment.expression import ITE, BinaryOp, Const, Convert, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase

_MAX_DEPTH = 8


def _int_const(expr: Expression) -> int | None:
    return expr.value_int if isinstance(expr, Const) and isinstance(expr.value, int) else None


def _log2(value: int | None) -> int | None:
    if value is None or value <= 0 or value & (value - 1):
        return None
    return value.bit_length() - 1


def scaled_bool(expr: Expression, depth: int = 0) -> tuple[Expression, int, bool] | None:
    """
    For an expression whose value is exactly ``zext(b) << k`` (``zext(!b) << k`` if negated) for a 1-bit ``b`` and
    ``k < expr.bits``, return (b, k, negated).
    """
    if depth > _MAX_DEPTH:
        return None
    if isinstance(expr, Convert):
        if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
            return None
        if expr.from_bits == 1:
            return (expr.operand, 0, False) if expr.to_bits > 1 and not expr.is_signed else None
        inner = scaled_bool(expr.operand, depth + 1)
        if inner is None or inner[1] >= expr.to_bits:
            return None
        if expr.is_signed and expr.to_bits > expr.from_bits and inner[1] == expr.from_bits - 1:
            # the bit is the sign bit
            return None
        return inner
    if isinstance(expr, ITE):
        if expr.cond.bits != 1:
            return None
        t, f = _int_const(expr.iftrue), _int_const(expr.iffalse)
        if f == 0 and (k := _log2(t)) is not None and k < expr.bits:
            return expr.cond, k, False
        if t == 0 and (k := _log2(f)) is not None and k < expr.bits:
            return expr.cond, k, True
        return None
    if not isinstance(expr, BinaryOp) or expr.floating_point:
        return None
    op0, op1 = expr.operands
    if expr.op == "Mul":
        for base, factor in ((op0, op1), (op1, op0)):
            j = _log2(_int_const(factor))
            if j is None or base.bits != expr.bits:
                continue
            inner = scaled_bool(base, depth + 1)
            if inner is not None and inner[1] + j < expr.bits:
                return inner[0], inner[1] + j, inner[2]
        return None
    if expr.op in {"Shl", "Shr"} and op0.bits == expr.bits:
        j = _int_const(op1)
        if j is None:
            return None
        inner = scaled_bool(op0, depth + 1)
        if inner is None:
            return None
        k = inner[1] + j if expr.op == "Shl" else inner[1] - j
        return (inner[0], k, inner[2]) if 0 <= k < expr.bits else None
    if expr.op == "And" and op0.bits == expr.bits:
        for value, mask in ((op0, op1), (op1, op0)):
            m = _int_const(mask)
            if m is None:
                continue
            inner = scaled_bool(value, depth + 1)
            if inner is not None and (m >> inner[1]) & 1:
                return inner
        return None
    return None


class BoolScaledMask(PeepholeOptimizationExprBase):
    """
    Simplify a boolean scaled by a power of two, ``s = zext(b) << k`` for a 1-bit ``b``:

    - ``s & M`` => ``s`` when bit ``k`` of ``M`` is set
    - ``s >> j`` => ``zext(b) * 2**(k-j)`` for ``j <= k``
    - ``s != 0`` => ``b`` and ``s == 0`` => ``!b``

    ``s`` may be spelt with ``*``, ``<<``, ``>>``, masks, zero-extensions, truncations that keep bit ``k``, or
    ``b ? 2**k : 0``.
    """

    __slots__ = ()

    NAME = "(zext(b) << k) & (1 << k) => zext(b) << k; (zext(b) << k) != 0 => b"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.floating_point:
            return None
        op0, op1 = expr.operands
        if expr.op == "And":
            for value, mask in ((op0, op1), (op1, op0)):
                m = _int_const(mask)
                if m is None or value.bits != expr.bits:
                    continue
                inner = scaled_bool(value)
                if inner is not None and (m >> inner[1]) & 1:
                    return value
            return None
        if expr.op == "Shr":
            j = _int_const(op1)
            if j is None or j == 0 or op0.bits != expr.bits:
                return None
            inner = scaled_bool(op0)
            if inner is None or inner[1] < j:
                return None
            return self._scaled(expr, self._bool(inner), inner[1] - j)
        if expr.op in {"CmpEQ", "CmpNE"} and _int_const(op1) == 0:
            if isinstance(op0, Convert) and op0.from_bits == 1:
                # left to the conversion peepholes
                return None
            inner = scaled_bool(op0)
            if inner is None:
                return None
            b, _, negated = inner
            if negated == (expr.op == "CmpNE"):
                return UnaryOp(expr.idx, "Not", b, bits=1, **expr.tags)
            return b
        return None

    def _bool(self, inner: tuple[Expression, int, bool]) -> Expression:
        b, _, negated = inner
        return UnaryOp(self.manager.next_atom(), "Not", b, bits=1, **b.tags) if negated else b

    def _scaled(self, expr: Expression, b: Expression, k: int) -> Expression:
        conv = Convert(self.manager.next_atom(), 1, expr.bits, False, b, **expr.tags)
        if k == 0:
            return conv
        return BinaryOp(
            expr.idx,
            "Mul",
            [conv, Const(self.manager.next_atom(), 1 << k, expr.bits)],
            False,
            bits=expr.bits,
            **expr.tags,
        )
