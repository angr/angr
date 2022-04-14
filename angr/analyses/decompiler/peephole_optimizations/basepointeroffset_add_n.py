from ailment.expression import BinaryOp, BasePointerOffset, Const

from .base import PeepholeOptimizationExprBase


class BasePointerOffsetAddN(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "(Ptr - M) + N => Ptr - (M - N)"
    expr_classes = (BinaryOp, )  # all expressions are allowed

    def optimize(self, expr: BinaryOp):

        if (expr.op in ("Add", "Sub")
                and isinstance(expr.operands[0], BasePointerOffset)
                and isinstance(expr.operands[1], Const)
        ):
            offset = expr.operands[0].offset
            if expr.op == "Add":
                offset += expr.operands[1].value
            else:  # expr.op == "Sub"
                offset -= expr.operands[1].value

            # convert offset to a signed integer
            max_int = (1 << (self.project.arch.bits - 1)) - 1
            if offset > max_int:
                offset -= 1 << self.project.arch.bits

            r = expr.operands[0].copy()
            r.offset = offset
            return r

        return None
