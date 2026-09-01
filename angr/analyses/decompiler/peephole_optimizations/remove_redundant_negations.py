from angr.ailment.expression import UnaryOp, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantNegations(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant Negations"
    expr_classes = (UnaryOp,)  # all expressions are allowed

    @staticmethod
    def _complement_without_new_negation(expr, bits):
        if getattr(expr, "bits", None) != bits:
            return None

        if isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg":
            return expr.operand

        if isinstance(expr, Const):
            return Const(expr.idx, (~expr.value) & ((1 << bits) - 1), bits, **expr.tags)

        return None

    def optimize(self, expr: UnaryOp, **kwargs):
        # Neg(Neg(expr)) ==> expr
        if expr.op == "BitwiseNeg" and isinstance(expr.operand, UnaryOp) and expr.operand.op == "BitwiseNeg":
            return expr.operand.operand

        # Neg(Const + Neg(expr)) ==> expr - Const
        if (expr.op == "BitwiseNeg"
            and isinstance(expr.operand, BinaryOp)
            and expr.operand.op == "Add"
            and isinstance(expr.operand.operands[0], Const)
            and isinstance(expr.operand.operands[1], UnaryOp)
            and expr.operand.operands[1].op == "BitwiseNeg"
        ):
            expr_0 = expr.operand.operands[1].operand
            expr_1 = expr.operand.operands[0]
            return BinaryOp(expr.idx, "Sub", [expr_0, expr_1], False, bits=expr_0.bits, **expr.tags)

        # Neg(Neg(expr) - other) ==> expr + other
        #
        # The mirror of the rule above, and the sign flips with the shape: ~(~x - y) is x + y where
        # ~(y + ~x) is x - y. Holds for any subtrahend, not just a constant.
        if (
            expr.op == "BitwiseNeg"
            and isinstance(expr.operand, BinaryOp)
            and expr.operand.op == "Sub"
            and isinstance(expr.operand.operands[0], UnaryOp)
            and expr.operand.operands[0].op == "BitwiseNeg"
        ):
            expr_0 = expr.operand.operands[0].operand
            expr_1 = expr.operand.operands[1]
            if expr_0.bits == expr.bits and expr_1.bits == expr.bits:
                return BinaryOp(expr.idx, "Add", [expr_0, expr_1], False, bits=expr.bits, **expr.tags)

        # Neg(a | b) ==> Neg(a) & Neg(b)
        # Neg(a & b) ==> Neg(a) | Neg(b)
        #
        # Keep this conservative: only apply it when both complements can be
        # materialized without introducing new BitwiseNeg nodes.
        if expr.op == "BitwiseNeg" and isinstance(expr.operand, BinaryOp) and expr.operand.op in {"And", "Or"}:
            operand_0, operand_1 = expr.operand.operands
            new_operand_0 = self._complement_without_new_negation(operand_0, expr.bits)
            new_operand_1 = self._complement_without_new_negation(operand_1, expr.bits)

            if new_operand_0 is not None and new_operand_1 is not None:
                new_op = "And" if expr.operand.op == "Or" else "Or"
                return BinaryOp(
                    expr.idx,
                    new_op,
                    [new_operand_0, new_operand_1],
                    expr.operand.signed,
                    bits=expr.bits,
                    **expr.tags,
                )

        return None
