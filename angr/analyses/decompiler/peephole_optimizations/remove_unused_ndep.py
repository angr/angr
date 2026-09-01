from angr.ailment.expression import DirtyExpression, Const, VEXCCallExpression

from .base import PeepholeOptimizationExprBase


class RemoveUnusedNdeps(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = ""
    expr_classes = (DirtyExpression,)

    def optimize(self, expr: DirtyExpression, **kwargs):

        if expr.dirty_expr.cee_name == "amd64g_calculate_rflags_all" and not isinstance(expr.dirty_expr.operands[-1], Const):
            # these operations do not use the ndep value so we can zero it out
            if isinstance(expr.dirty_expr.operands[0], Const) and expr.dirty_expr.operands[0].value in [0,1,2,3,4,5,6,7,8,17,18,19,20]:
                vex_call_expr = VEXCCallExpression(idx=expr.dirty_expr.idx, cee_name=expr.dirty_expr.cee_name,
                                                   operands=(expr.dirty_expr.operands[0],
                                                             expr.dirty_expr.operands[1],
                                                             expr.dirty_expr.operands[2],
                                                             Const(None, 0, expr.dirty_expr.operands[-1].bits)),
                                                   bits=expr.dirty_expr.bits, **expr.dirty_expr.tags)
                return DirtyExpression(idx=expr.idx, dirty_expr=vex_call_expr, bits=expr.bits, **expr.tags)

        return None