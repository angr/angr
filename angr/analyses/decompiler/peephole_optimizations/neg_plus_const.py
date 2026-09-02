from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, UnaryOp

from .base import PeepholeOptimizationExprBase


def _as_constant_minus(expr, bits: int) -> tuple[int, object] | None:
    """
    Read ``expr`` as ``K - inner`` for a constant ``K``, or return None.

    Every negation is an affine function of its operand -- ``-x`` is ``0 - x`` and ``~x`` is
    ``-1 - x`` -- and a constant displacement underneath it just shifts ``K``.  Naming that one
    form collapses the whole family instead of matching each shape separately.
    """
    if not isinstance(expr, UnaryOp) or expr.op not in ("Neg", "BitwiseNeg"):
        return None
    base = -1 if expr.op == "BitwiseNeg" else 0
    inner = expr.operand
    if getattr(inner, "bits", None) != bits:
        return None

    if isinstance(inner, BinaryOp) and inner.op in ("Add", "Sub"):
        left, right = inner.operands
        if isinstance(right, Const) and isinstance(right.value, int):
            # -(y - c) is c - y; -(y + c) is -c - y, and BitwiseNeg shifts both by one more
            displacement = right.value if inner.op == "Sub" else -right.value
            return base + displacement, left
        if inner.op == "Add" and isinstance(left, Const) and isinstance(left.value, int):
            return base - left.value, right
    return base, inner


class NegPlusConstToSub(PeepholeOptimizationExprBase):
    """
    Fold a negation added to a constant into a single subtraction.

    ``-(x) + 64`` is ``64 - x`` and ``-(x - 99) + 64`` is ``163 - x``.  A VM emits these by the
    hundred; left alone they read like mixed boolean-arithmetic and bury the expressions that
    genuinely are.
    """

    __slots__ = ()

    NAME = "-(x) + C => C - x"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in ("Add", "Sub") or len(expr.operands) != 2:
            return None

        op0, op1 = expr.operands
        # `C - negation` is not this shape: the negation has to be the one being displaced.
        candidates = ((op0, op1), (op1, op0)) if expr.op == "Add" else ((op0, op1),)
        for negated, other in candidates:
            if not isinstance(other, Const) or not isinstance(other.value, int):
                continue
            split = _as_constant_minus(negated, expr.bits)
            if split is None:
                continue
            constant, inner = split
            displacement = other.value if expr.op == "Add" else -other.value
            total = (constant + displacement) & ((1 << expr.bits) - 1)
            if expr.bits > 16 and total >= 1 << (expr.bits - 1):
                # A negative constant prints as a full-width hex literal, longer than the negation
                # it replaced -- but only at wide widths.  At 8 or 16 bits `163 - x` is perfectly
                # readable even though 163 is "negative" as a signed byte, and refusing it here
                # was leaving exactly the expressions this pass exists to fold.
                continue
            return BinaryOp(
                expr.idx,
                "Sub",
                [Const(self.manager.next_atom(), total, expr.bits), inner],
                expr.signed,
                bits=expr.bits,
                **expr.tags,
            )
        return None
