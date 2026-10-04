from __future__ import annotations

from angr.ailment.expression import ITE, BinaryOp, Const, Convert, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase


def _bool_of(expr: Expression) -> Expression | None:
    """c for a 0/1 value Conv(1->N, c), else None."""
    if (
        isinstance(expr, Convert)
        and expr.from_bits == 1
        and expr.from_type == expr.to_type == Convert.TYPE_INT
        and not expr.is_signed
    ):
        return expr.operand
    return None


class SbbMaskToITE(PeepholeOptimizationExprBase):
    """
    Turn the branchless select built from a carry (cmp x, 1; sbb eax, eax; and eax, K; sub eax, D) into an ITE:

        (-Conv(1->N, c)) & K       ==>  ITE(c, K, 0)
        ITE(c, K0, K1) +/- D       ==>  ITE(c, K0 +/- D, K1 +/- D)
        b <u 1 (b is 1-bit)        ==>  !b
        ITE(!c, a, b)              ==>  ITE(c, b, a)
    """

    __slots__ = ()

    NAME = "Branchless carry-mask select to ITE"
    expr_classes = (BinaryOp, ITE)

    def optimize(self, expr: BinaryOp | ITE, **kwargs):
        if isinstance(expr, ITE):
            if isinstance(expr.cond, UnaryOp) and expr.cond.op == "Not":
                return ITE(expr.idx, expr.cond.operand, expr.iffalse, expr.iftrue, **expr.tags)
            return None

        if expr.floating_point:
            return None
        op0, op1 = expr.operands

        if expr.op == "CmpLT" and not expr.signed and op0.bits == 1 and isinstance(op1, Const) and op1.value == 1:
            return UnaryOp(expr.idx, "Not", op0, bits=1, **expr.tags)

        if not (isinstance(op1, Const) and isinstance(op1.value, int)):
            return None
        mask = (1 << expr.bits) - 1

        if expr.op == "And" and isinstance(op0, UnaryOp) and op0.op == "Neg":
            cond = _bool_of(op0.operand)
            if cond is None:
                return None
            return ITE(
                expr.idx,
                cond,
                Const(self.manager.next_atom(), op1.value & mask, expr.bits),
                Const(self.manager.next_atom(), 0, expr.bits),
                **expr.tags,
            )

        if expr.op in {"Add", "Sub"} and isinstance(op0, ITE):
            t, f = op0.iftrue, op0.iffalse
            if not (
                isinstance(t, Const) and isinstance(t.value, int) and isinstance(f, Const) and isinstance(f.value, int)
            ):
                return None
            d = op1.value if expr.op == "Add" else -op1.value
            return ITE(
                expr.idx,
                op0.cond,
                Const(self.manager.next_atom(), (t.value + d) & mask, expr.bits),
                Const(self.manager.next_atom(), (f.value + d) & mask, expr.bits),
                **expr.tags,
            )
        return None
