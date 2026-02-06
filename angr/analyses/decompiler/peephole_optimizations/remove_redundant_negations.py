from ailment.expression import UnaryOp, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantNegations(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant Negations"
    expr_classes = (UnaryOp,)  # all expressions are allowed

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

        return None
