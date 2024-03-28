from ailment.expression import ITE, Convert, DirtyExpression, VEXCCallExpression, Tmp, BinaryOp, Const


from .base import PeepholeOptimizationExprBase


class RemoveIdFlag(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove id, ac and d flags"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        if (
                isinstance(expr.operands[0], DirtyExpression)
                and expr.operands[0].dirty_expr.cee_name in ["amd64g_calculate_rflags_all"]
        ):
            #make sure the left arg is calculate_eflags_all
            if expr.op == "Or" and isinstance(expr.operands[1], BinaryOp) and expr.operands[1].op == "And":
                if isinstance(expr.operands[1].operands[1], Const) and expr.operands[1].operands[1].value in [0x200000, 0x400, 0x40000]:
                    return expr.operands[0]

        return None
