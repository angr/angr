from ailment.expression import BinaryOp, BasePointerOffset, Const

from .base import PeepholeOptimizationExprBase


class BasePointerOffsetAndMask(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Ptr & mask => Ptr"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op == "And" and isinstance(expr.operands[0], BasePointerOffset) and isinstance(expr.operands[1], Const):
            # is it a mask?
            mask = expr.operands[1].value
            if mask not in {
                0xFFFE,
                0xFFFC,
                0xFFF8,
                0xFFF0,
                0xFFFF_FFFE,
                0xFFFF_FFFC,
                0xFFFF_FFF8,
                0xFFFF_FFF0,
                0xFFFF_FFFF_FFFF_FFFE,
                0xFFFF_FFFF_FFFF_FFFC,
                0xFFFF_FFFF_FFFF_FFF8,
                0xFFFF_FFFF_FFFF_FFF0,
            }:
                return None

            # we ignore this mask
            return expr.operands[0]

        return None
