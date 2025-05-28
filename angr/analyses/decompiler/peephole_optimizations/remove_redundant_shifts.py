# pylint:disable=no-self-use,too-many-boolean-expressions
from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase
from .utils import get_expr_shift_left_amount


class RemoveRedundantShifts(PeepholeOptimizationExprBase):
    """
    Remove redundant bitshift operations.
    """

    __slots__ = ()

    NAME = "Remove redundant bitshifts"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        # (expr << N) >> N  ==> Convert((M-N)->M, Convert(M->(M-N), expr))
        if expr.op in ("Shr", "Sar") and isinstance(expr.operands[1], Const):
            expr_a = expr.operands[0]
            n0 = expr.operands[1].value
            if isinstance(expr_a, BinaryOp) and expr_a.op in {"Shl", "Mul"} and isinstance(expr_a.operands[1], Const):
                n1 = get_expr_shift_left_amount(expr_a)
                if n0 == n1:
                    inner_expr = expr_a.operands[0]
                    conv_inner_expr = Convert(
                        None,
                        expr_a.bits,
                        expr_a.bits - n0,
                        expr.op == "Sar",  # is_signed
                        inner_expr,
                        **expr.tags,
                    )
                    return Convert(
                        None,
                        expr_a.bits - n0,
                        expr.bits,
                        False,
                        conv_inner_expr,
                        **expr.tags,
                    )

        # expr << 0  ==>  expr
        # expr >> 0  ==>  expr
        if expr.op in {"Shl", "Shr", "Sar"} and isinstance(expr.operands[1], Const) and expr.operands[1].value == 0:
            return expr.operands[0]

        mask_hi32bits = 0xFFFFFFFF_00000000
        exp_32bits = 0x1_00000000
        if (
            expr.op == "Shr"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == 32
            and isinstance(expr.operands[0], BinaryOp)
            and expr.operands[0].op == "Or"
        ):
            op0, op1 = expr.operands[0].operands
            if (
                isinstance(op1, Convert)
                and op1.from_bits == 32
                and op1.to_bits == 64
                and op1.from_type == Convert.TYPE_INT
                and op1.to_type == Convert.TYPE_INT
                and isinstance(op0, BinaryOp)
                and op0.op == "And"
            ):
                # (expr<64-bits> & 0xffffffff_00000000) | Conv(32->64, expr<32-bits>)) >> 32  ==>  expr<64-bits> >> 32
                inner_op0, inner_op1 = op0.operands
                if isinstance(inner_op1, Const) and inner_op1.value == mask_hi32bits:
                    if (
                        isinstance(inner_op0, BinaryOp)
                        and isinstance(inner_op0.operands[1], Const)
                        and inner_op0.operands[1].value == exp_32bits
                    ):
                        return inner_op0.operands[0]
                    return BinaryOp(expr.idx, "Shr", [inner_op0, expr.operands[1]], expr.signed, **expr.tags)
                return BinaryOp(expr.idx, "Shr", [op0, expr.operands[1]], expr.signed, **expr.tags)

            for op0, op1 in [expr.operands[0].operands, expr.operands[0].operands[::-1]]:
                # ((v11 & 0xffff_ffff | 10.0 * 0x1_00000000) >> 32)   ==>   10.0
                if (
                    isinstance(op0, BinaryOp)
                    and op0.op == "And"
                    and isinstance(op0.operands[1], Const)
                    and op0.operands[1].value == 0xFFFF_FFFF
                    and isinstance(op1, BinaryOp)
                    and op1.op == "Mul"
                    and isinstance(op1.operands[1], Const)
                    and op1.operands[1].value == 0x1_0000_0000
                ):
                    return op1.operands[0]

        return None
