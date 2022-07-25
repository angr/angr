from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class EagerEvaluation(PeepholeOptimizationExprBase):
    """
    Eagerly evaluates certain types of expressions.
    """
    __slots__ = ()

    NAME = "Eager expression evaluation"
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
        elif expr.op == "Sub" \
                and isinstance(expr.operands[0], Const) \
                and isinstance(expr.operands[1], Const):
            mask = (2 << expr.bits) - 1
            new_expr = Const(expr.idx, None,
                             (expr.operands[0].value - expr.operands[1].value) & mask,
                             expr.bits,
                             **expr.tags)
            return new_expr

        elif expr.op == "And" \
                and isinstance(expr.operands[0], Const) \
                and isinstance(expr.operands[1], Const):
            new_expr = Const(expr.idx, None,
                             (expr.operands[0].value & expr.operands[1].value),
                             expr.bits,
                             **expr.tags)
            return new_expr

        elif expr.op == "Mul" \
                and isinstance(expr.operands[1], Const) \
                and expr.operands[1].value == 1:
            return expr.operands[0]

        elif expr.op in {"Shr", "Sar"} \
                and isinstance(expr.operands[1], Const) \
                and isinstance(expr.operands[0], BinaryOp) \
                and expr.operands[0].op == "Shr" \
                and isinstance(expr.operands[0].operands[1], Const):
            # (a >> M) >> N  ==>  a >> (M + N)
            const_a = expr.operands[0].operands[1]
            const_b = expr.operands[1]
            const = Const(const_b.idx, None, const_a.value + const_b.value, const_b.bits, **const_b.tags)
            return BinaryOp(expr.idx, expr.op,
                            (expr.operands[0].operands[0], const),
                            False,
                            bits=expr.bits,
                            **expr.tags)

        return None
