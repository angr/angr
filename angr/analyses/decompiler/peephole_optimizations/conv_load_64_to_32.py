from __future__ import annotations

from angr.ailment.expression import Convert, Load

from .base import PeepholeOptimizationExprBase


class ConvLoad(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Conv(64->32, Load(x,8)) ==> Load(x,4)"
    expr_classes = (Convert,)

    def optimize(self, expr: Convert, **kwargs):
        # integer truncation only; on little-endian the low half sits at the same address
        if (
            expr.from_bits == 64
            and expr.to_bits == 32
            and expr.from_type == Convert.TYPE_INT
            and expr.to_type == Convert.TYPE_INT
        ):
            if isinstance(expr.operand, Load) and expr.operand.size == 8 and expr.operand.endness == "Iend_LE":
                return Load(expr.operand.idx, expr.operand.addr, 4, expr.operand.endness, **expr.tags)
        return None
