from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class SignBitTest(PeepholeOptimizationExprBase):
    """
    ``((x >> (n-1)) & 1) != 0`` and ``(x >> (n-1)) == 1``  =>  ``x <s 0``; the negated forms become ``x >=s 0``.
    """

    __slots__ = ()

    NAME = "(x >> (n-1)) & 1 != 0 => x < 0"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in {"CmpEQ", "CmpNE"}:
            return None
        lhs, rhs = expr.operands
        if not (isinstance(rhs, Const) and rhs.value in (0, 1)):
            return None
        is_neg = (expr.op == "CmpNE") == (rhs.value == 0)

        e = lhs
        if isinstance(e, Convert) and e.from_bits > e.to_bits:
            e = e.operand
        if isinstance(e, BinaryOp) and e.op == "And" and isinstance(e.operands[1], Const) and e.operands[1].value == 1:
            e = e.operands[0]
        if isinstance(e, Convert) and e.from_bits > e.to_bits:
            e = e.operand
        if not (isinstance(e, BinaryOp) and e.op == "Shr" and isinstance(e.operands[1], Const)):
            return None
        x = e.operands[0]
        if e.operands[1].value != x.bits - 1 or x.bits < 8:
            return None
        zero = Const(self.manager.next_atom(), 0, x.bits)
        return BinaryOp(expr.idx, "CmpLT" if is_neg else "CmpGE", [x, zero], True, bits=1, **expr.tags)
