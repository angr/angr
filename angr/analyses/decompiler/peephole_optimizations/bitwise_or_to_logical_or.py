from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class BitwiseOrToLogicalOr(PeepholeOptimizationExprBase):
    """
    Perform the following two simplifications:

    1. (a | b) == 0  ==>  (a == 0) && (b == 0)
    2. (a | b) != 0  ==>  (a != 0) || (b != 0)
    """

    __slots__ = ()

    NAME = "(a | b) == 0 => (a == 0) && (b == 0) ; (a | b) != 0 => (a != 0) || (b != 0)"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        if (
            expr.op in {"CmpEQ", "CmpNE"}
            and isinstance(expr.operands[0], BinaryOp)
            and expr.operands[0].op == "Or"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == 0
        ):
            inner = expr.operands[0]
            new_left = BinaryOp(inner.idx, expr.op, (inner.operands[0], expr.operands[1]), False, bits=1, **inner.tags)
            new_right = BinaryOp(inner.idx, expr.op, (inner.operands[1], expr.operands[1]), False, bits=1, **inner.tags)
            op = "LogicalOr" if expr.op == "CmpNE" else "LogicalAnd"
            new_expr = BinaryOp(expr.idx, op, (new_left, new_right), False, bits=expr.bits, **expr.tags)
            return new_expr

        return expr
