from ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class ASubADivConstMulConst(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "a - (a / N) * N => a % N"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp):
        if (
            expr.op == "Sub"
            and len(expr.operands) == 2
            and isinstance(expr.operands[1], BinaryOp)
            and expr.operands[1].op == "Mul"
            and isinstance(expr.operands[1].operands[1], Const)
        ):
            a0, op1 = expr.operands
            op1_left = op1.operands[0]
            mul_const = expr.operands[1].operands[1]

            if (
                isinstance(op1_left, Convert)
                and isinstance(a0, Convert)
                and op1_left.to_bits == a0.to_bits
                and op1_left.from_bits == a0.from_bits
            ):
                # Convert(a) - (Convert(a / N)) * N  ==>  Convert(a) % N
                conv_expr = a0
                a0 = a0.operand
                op1_left = op1_left.operand
            else:
                conv_expr = None

            if isinstance(op1_left, BinaryOp) and op1_left.op == "Div" and isinstance(op1_left.operands[1], Const):
                # a - (a / N) * N  ==>  a % N
                a1 = op1_left.operands[0]
                div_const = op1_left.operands[1]

                if a0.likes(a1) and mul_const.value == div_const.value:
                    operands = [a0, div_const]
                    mod = BinaryOp(expr.idx, "DivMod", operands, False, bits=a0.bits, **expr.tags)
                    if conv_expr is not None:
                        mod = Convert(
                            conv_expr.idx,
                            conv_expr.from_bits,
                            conv_expr.to_bits,
                            conv_expr.is_signed,
                            mod,
                            **conv_expr.tags,
                        )
                    return mod

        return None
