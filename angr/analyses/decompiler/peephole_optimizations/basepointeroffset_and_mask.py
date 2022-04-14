from ailment.expression import BinaryOp, BasePointerOffset, Const

from .base import PeepholeOptimizationExprBase


class BasePointerOffsetAndMask(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Ptr & mask => Ptr"
    expr_classes = (BinaryOp, )  # all expressions are allowed

    def optimize(self, expr: BinaryOp):

        if (expr.op == "And"
                and isinstance(expr.operands[0], BasePointerOffset)
                and isinstance(expr.operands[1], Const)
        ):
            # is it a mask?
            mask = expr.operands[1].value
            if mask not in {
                0xfffe, 0xfffc, 0xfff8, 0xfff0,
                0xffff_fffe, 0xffff_fffc, 0xffff_fff8, 0xffff_fff0,
                0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_fffc, 0xffff_ffff_ffff_fff8, 0xffff_ffff_ffff_fff0,
            }:
                return None

            # we ignore this mask
            return expr.operands[0]

        return None
