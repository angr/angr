from ailment.expression import Convert, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ConvASub0ShrAnd(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Conv(M->1, (expr >> N) & 1) => expr < 0"
    expr_classes = (Convert,)  # all expressions are allowed

    def optimize(self, expr: Convert):
        # Conv(M->1, ((expr) >> N) & 1) => expr < 0
        # Conv(M->1, ((expr - 0) >> N) & 1) => expr < 0
        if expr.to_bits == 1:
            if (
                isinstance(expr.operand, BinaryOp)
                and expr.operand.op == "And"
                and isinstance(expr.operand.operands[1], Const)
                and expr.operand.operands[1].value == 1
            ):
                # taking a single bit
                inner_expr = expr.operand.operands[0]
                if (
                    isinstance(inner_expr, BinaryOp)
                    and inner_expr.op == "Shr"
                    and isinstance(inner_expr.operands[1], Const)
                ):
                    # right-shifting with a constant
                    shr_amount = inner_expr.operands[1].value
                    if shr_amount == 7:
                        # int8_t
                        to_bits = 8
                    elif shr_amount == 15:
                        # int16_t
                        to_bits = 16
                    elif shr_amount == 31:
                        # int32_t
                        to_bits = 32
                    elif shr_amount == 63:
                        # int64_t
                        to_bits = 64
                    else:
                        # unsupported
                        return None

                    real_expr = inner_expr.operands[0]

                    if (
                        isinstance(real_expr, BinaryOp)
                        and real_expr.op == "Sub"
                        and isinstance(real_expr.operands[1], Const)
                        and real_expr.operands[1].value == 0
                    ):
                        real_expr = real_expr.operands[0]

                    cvt = Convert(expr.idx, real_expr.bits, to_bits, False, real_expr, **expr.tags)
                    cmp = BinaryOp(
                        None,
                        "CmpLT",
                        (
                            cvt,
                            Const(None, None, 0, to_bits),
                        ),
                        True,
                        **expr.tags,
                    )
                    return cmp

        return None
