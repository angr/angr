from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantShiftsAroundComparators(PeepholeOptimizationExprBase):
    """
    Remove redundant bitshifts for both operands around a comparison operator.

    More cases can be added in the future as we encounter them.
    """

    __slots__ = ()

    NAME = "Remove redundant bitshifts for operands around a comparator"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(
        self, expr: BinaryOp, stmt_idx: int | None = None, block=None, **kwargs
    ):  # pylint:disable=unused-argument
        # (expr_0 << N) < (expr_1 << N)  ==> expr_0 << expr_1
        # FIXME: This optimization is unsafe but seems to work for all existing case
        if expr.op in {"CmpLE", "CmpLT", "CmpEQ", "CmpNE", "CmpGE", "CmpGT"}:
            op0, op1 = expr.operands
            if (
                isinstance(op0, BinaryOp)
                and op0.op == "Shl"
                and isinstance(op1, BinaryOp)
                and op1.op == "Shl"
                and isinstance(op0.operands[1], Const)
                and isinstance(op1.operands[1], Const)
                and op0.operands[1].value == op1.operands[1].value
            ):
                return BinaryOp(
                    expr.idx,
                    expr.op,
                    [op0.operands[0], op1.operands[0]],
                    expr.signed,
                    bits=expr.bits,
                    floating_point=expr.floating_point,
                    rounding_mode=expr.rounding_mode,
                    **expr.tags,
                )

            # might have been rewritten to multiplications
            if (
                isinstance(op0, BinaryOp)
                and op0.op == "Mul"
                and isinstance(op0.operands[1], Const)
                and op0.operands[1].is_int
            ):
                op0_op = op0.operands[0]
                mul_0 = op0.operands[1].value_int
                mul_1 = None
                op1_op = None
                if (
                    isinstance(op1, BinaryOp)
                    and op1.op == "Mul"
                    and isinstance(op1.operands[1], Const)
                    and op1.operands[1].is_int
                ):
                    op1_op = op1.operands[0]
                    mul_1 = op1.operands[1].value_int
                elif isinstance(op1, Const):
                    op1_op = None
                    mul_1 = op1.value_int

                if mul_1 is not None:
                    common_shift_amount = self._get_common_shift_amount(mul_0, mul_1)
                    if common_shift_amount > 0:
                        new_mul_0 = Const(None, None, mul_0 >> common_shift_amount, expr.bits)
                        new_mul_1 = Const(None, None, mul_1 >> common_shift_amount, expr.bits)
                        new_cmp_0 = BinaryOp(op0.idx, "Mul", [op0_op, new_mul_0], op0.signed, bits=op0.bits, **op0.tags)
                        new_cmp_1 = (
                            BinaryOp(op1.idx, "Mul", [op1_op, new_mul_1], op1.signed, bits=op1.bits, **op1.tags)
                            if op1_op is not None
                            else new_mul_1
                        )
                        return BinaryOp(
                            expr.idx,
                            expr.op,
                            [new_cmp_0, new_cmp_1],
                            expr.signed,
                            bits=expr.bits,
                            floating_point=expr.floating_point,
                            rounding_mode=expr.rounding_mode,
                            **expr.tags,
                        )

        return None

    @staticmethod
    def _get_common_shift_amount(v0: int, v1: int) -> int:
        if v0 == 0 or v1 == 0:
            return 0
        shift_amount = 0
        while (v0 & 1) == 0 and (v1 & 1) == 0:
            if v0 & 0xFFFF == 0 and v1 & 0xFFFF == 0:
                v0 >>= 16
                v1 >>= 16
                shift_amount += 16
            elif v0 & 0xFF == 0 and v1 & 0xFF == 0:
                v0 >>= 8
                v1 >>= 8
                shift_amount += 8
            elif v0 & 0xF == 0 and v1 & 0xF == 0:
                v0 >>= 4
                v1 >>= 4
                shift_amount += 4
            else:
                v0 >>= 1
                v1 >>= 1
                shift_amount += 1
        return shift_amount
