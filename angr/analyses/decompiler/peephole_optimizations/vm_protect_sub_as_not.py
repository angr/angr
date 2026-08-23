from angr.ailment.expression import BinaryOp, UnaryOp

from .base import PeepholeOptimizationExprBase


class VMPSubAsNot(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant Ands"
    expr_classes = (UnaryOp,)  # all expressions are allowed

    def optimize(self, expr: UnaryOp, **kwargs):
        # not(not(rsp)+0x18) == rsp-0x18 an
        if (
            expr.op == "BitwiseNeg" and isinstance(expr.operand, BinaryOp)
            and expr.operand.op == "Add"
            and isinstance(expr.operand.operands[0], UnaryOp)
            and expr.operand.operands[0].op == "BitwiseNeg"
        ):
            return BinaryOp(expr.operand.idx, "Sub", [expr.operand.operands[0].operand, expr.operand.operands[1]], expr.operand.signed,
                            **expr.operand.tags,)

        return None
