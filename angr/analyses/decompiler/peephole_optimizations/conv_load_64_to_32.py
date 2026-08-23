from angr.ailment.expression import Convert, BinaryOp, Const, Load, StackBaseOffset

from .base import PeepholeOptimizationExprBase


class ConvLoad(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Conv(64->32, Load(x,8)) ==> Load(x,4)"
    expr_classes = (Convert,)

    def optimize(self, expr: Convert, **kwargs):
        if expr.from_bits == 64 and expr.to_bits == 32:
            if isinstance(expr.operand, Load) and expr.operand.size == 8:
                return Load(expr.operand.idx, expr.operand.addr, 4, expr.operand.endness, **expr.tags)
        return None
