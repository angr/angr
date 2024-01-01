from ailment.expression import ITE, Convert, DirtyExpression, VEXCCallExpression, Tmp, BinaryOp, Const


from .base import PeepholeOptimizationExprBase


class ThemidaCondSimplify(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Themida flag check simplifications"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        if (
                isinstance(expr.operands[0], DirtyExpression)
                and expr.operands[0].dirty_expr.cee_name == "x86g_calculate_eflags_all"
        ):
            #make sure the left arg is calculate_eflags_all
            if expr.op == "Or" and isinstance(expr.operands[1], Const):
                if (expr.operands[1].value & 0x40) >> 6 == 0:
                    # the 6th bit needs to be zero for the const operand, if checking zero bit in calc_cond
                    return expr.operands[0]
            elif (
                    expr.op == "Or" and isinstance(expr.operands[1], BinaryOp) and expr.operands[1].op == "And"
                    and isinstance(expr.operands[1].operands[1], Const)
                ):
                if (expr.operands[1].operands[1].value & 0x40) >> 6 == 0:
                    return expr.operands[0]

            elif expr.op == "And" and isinstance(expr.operands[1], Const):
                if (expr.operands[1].value & 0x40) >> 6 == 1:
                    # the 6th bit needs to be one for the const operand, if checking zero bit in calc_cond
                    return expr.operands[0]
        return None
