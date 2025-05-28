from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class RewriteConvMul(PeepholeOptimizationExprBase):
    """
    Rewrites multiplication to be inside conversion.
    """

    __slots__ = ()

    NAME = "Rewrite Conv Mul"
    expr_classes = (BinaryOp,)

    # Conv(64->32, (Conv(32->64, expr) * N<64>)) * N<32>)
    # => Conv(64->32, (Conv(32->64, expr) * N<64>) * Conv(32->64,N<32>))
    def optimize(self, expr: BinaryOp, **kwargs):
        if (
            expr.op == "Mul"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].bits == 32
            and isinstance(expr.operands[0], Convert)
            and expr.operands[0].from_bits > expr.operands[0].to_bits
        ):
            op0, op1 = expr.operands
            operand_expr = op0.operand
            if (
                isinstance(operand_expr, BinaryOp)
                and operand_expr.op == "Mul"
                and isinstance(operand_expr.operands[1], Const)
                and operand_expr.operands[1].bits == 64
            ):
                new_op1 = Convert(op1.idx, op1.bits, op0.from_bits, False, op1, **op1.tags)
                new_op0 = op0.operand
                new_expr = BinaryOp(expr.idx, "Mul", [new_op0, new_op1], expr.signed, **expr.tags)
                return Convert(new_expr.idx, op0.from_bits, op0.to_bits, False, new_expr, **expr.tags)

        return None
