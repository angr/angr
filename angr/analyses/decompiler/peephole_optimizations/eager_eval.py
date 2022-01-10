from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class EagerEvaluation(PeepholeOptimizationExprBase):
    """
    Eagerly evaluates certain types of expressions.
    """
    __slots__ = ()

    name = "Eager expression evaluation"
    expr_classes = (BinaryOp, )

    def optimize(self, expr: BinaryOp):

        if expr.op == "Add" \
                and isinstance(expr.operands[0], Const) \
                and isinstance(expr.operands[1], Const):
            mask = (2 << expr.bits) - 1
            new_expr = Const(expr.idx, None,
                             (expr.operands[0].value + expr.operands[1].value) & mask,
                             expr.bits,
                             **expr.tags)
            return new_expr

        return None
