from __future__ import annotations

from angr.ailment.expression import BinaryOp, UnaryOp

from .base import PeepholeOptimizationExprBase


class AddNegToSub(PeepholeOptimizationExprBase):
    """
    Rewrite an addition of a negated term as a subtraction. claripy folds `a - b` into the n-ary sum `a + (-b)`, so
    conditions converted back from claripy would otherwise read `a + -b`.
    """

    __slots__ = ()

    NAME = "a + (-b) => a - b"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op != "Add" or expr.vector_count is not None:
            return None

        op0, op1 = expr.operands
        if isinstance(op1, UnaryOp) and op1.op == "Neg":
            # Add(a, Neg(b)) ==> Sub(a, b)
            lhs, rhs = op0, op1.operand
        elif isinstance(op0, UnaryOp) and op0.op == "Neg":
            # Add(Neg(a), b) ==> Sub(b, a)
            lhs, rhs = op1, op0.operand
        else:
            return None

        return BinaryOp(
            expr.idx,
            "Sub",
            (lhs, rhs),
            expr.signed,
            bits=expr.bits,
            floating_point=expr.floating_point,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )
