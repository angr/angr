from __future__ import annotations

from angr.ailment.expression import Const, DirtyExpression, VEXCCallExpression

from .base import PeepholeOptimizationExprBase

# cc_op values whose flag computation never reads cc_ndep.
NDEP_UNUSED_OPS = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20})


class RemoveUnusedNdeps(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Zero out an unused cc_ndep"
    expr_classes = (DirtyExpression,)

    def optimize(self, expr, **kwargs):
        if getattr(expr, "callee", None) != "amd64g_calculate_rflags_all":
            return None
        operands = expr.operands
        if len(operands) != 4 or isinstance(operands[-1], Const):
            return None
        cc_op = operands[0]
        if not isinstance(cc_op, Const) or cc_op.value not in NDEP_UNUSED_OPS:
            return None
        # Zeroing the dead operand is what makes the ccall rewritable downstream.
        return VEXCCallExpression(
            expr.idx,
            expr.callee,
            (operands[0], operands[1], operands[2], Const(None, 0, operands[-1].bits)),
            bits=expr.bits,
            **expr.tags,
        )
