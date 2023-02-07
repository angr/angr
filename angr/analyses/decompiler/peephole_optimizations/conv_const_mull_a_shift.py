from ailment.expression import Convert, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ConvConstMullAShift(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Conv(64->32, (N * a) >> M) => a / N1"
    expr_classes = (Convert,)

    def optimize(self, expr: Convert):
        if expr.from_bits == 64 and expr.to_bits == 32:
            if (
                isinstance(expr.operand, BinaryOp)
                and expr.operand.op == "Shr"
                and isinstance(expr.operand.operands[1], Const)
            ):
                # (N * a) >> M  ==>  a / N1
                inner = expr.operand.operands[0]
                if isinstance(inner, BinaryOp) and inner.op == "Mull" and isinstance(inner.operands[0], Const):
                    C = inner.operands[0].value
                    X = inner.operands[1]
                    V = expr.operand.operands[1].value
                    ndigits = 5 if V == 32 else 6
                    divisor = self._check_divisor(pow(2, V), C, ndigits)
                    if divisor is not None:
                        new_const = Const(None, None, divisor, V)
                        new_div = BinaryOp(inner.idx, "Div", [X, new_const], inner.signed, **inner.tags)
                        return new_div

            elif isinstance(expr.operand, BinaryOp) and expr.operand.op in {"Add", "Sub"}:
                expr0, expr1 = expr.operand.operands
                if (
                    isinstance(expr0, BinaryOp)
                    and expr0.op in {"Shr", "Sar"}
                    and isinstance(expr0.operands[1], Const)
                    and isinstance(expr1, BinaryOp)
                    and expr1.op in {"Shr", "Sar"}
                    and isinstance(expr1.operands[1], Const)
                ):
                    if (
                        isinstance(expr0.operands[0], BinaryOp)
                        and expr0.operands[0].op in {"Mull", "Mul"}
                        and isinstance(expr0.operands[0].operands[1], Const)
                    ):
                        a0 = expr0.operands[0].operands[0]
                        a1 = expr1.operands[0]
                        if a0 == a1:
                            # (a * x >> M1) +/- (a >> M2)  ==>  a / N
                            C = expr0.operands[0].operands[1].value
                            X = a0
                            V = expr0.operands[1].value
                            ndigits = 5 if V == 32 else 6
                            divisor = self._check_divisor(pow(2, V), C, ndigits)
                            if divisor is not None:
                                new_const = Const(None, None, divisor, V)
                                new_div = BinaryOp(
                                    expr0.operands[0].idx,
                                    "Div",
                                    [X, new_const],
                                    expr0.operands[0].signed,
                                    **expr0.operands[0].tags,
                                )
                                # we cannot drop the convert
                                new_div = Convert(
                                    expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, new_div, **expr.tags
                                )
                                return new_div

    @staticmethod
    def _check_divisor(a, b, ndigits=6):
        divisor_1 = 1 + (a // b)
        divisor_2 = int(round(a / float(b), ndigits))
        return divisor_1 if divisor_1 == divisor_2 else None
