from ailment.expression import BinaryOp, Const, Load

from .base import PeepholeOptimizationExprBase


class RewriteConstantOffsetLoads(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Rewrite Load address with constant offsets"
    expr_classes = (Load,)  # all expressions are allowed

    def optimize(self, expr: Load, **kwargs):
        if (isinstance(expr.addr, BinaryOp)
            and expr.addr.op == "Add"
            and not isinstance(expr.addr.operands[0], Const)
            and isinstance(expr.addr.operands[1], Const)
        ):
            new_addr = BinaryOp(expr.idx, "Add", [expr.addr.operands[1], expr.addr.operands[0]], False, bits=expr.addr.bits, **expr.addr.tags)
            return Load(expr.idx, new_addr, expr.size, expr.endness, **expr.tags)

        return None
