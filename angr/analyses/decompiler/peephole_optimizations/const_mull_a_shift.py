# pylint:disable=too-many-boolean-expressions
from typing import Union

from ailment.expression import Convert, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ConstMullAShift(PeepholeOptimizationExprBase):
    """
    Convert expressions with right shifts into expressions with divisions.
    """

    __slots__ = ()

    NAME = "Conv(64->32, (N * a) >> M) => a / N1"
    expr_classes = (Convert, BinaryOp)

    def optimize(self, expr: Union[Convert, BinaryOp], **kwargs):
        r = None

        if isinstance(expr, Convert):
            if expr.from_bits == 64 and expr.to_bits == 32:
                r = self.optimize_binaryop(expr)

        elif isinstance(expr, BinaryOp):
            r = self.optimize_binaryop(expr)

        # keep size
        if r is not None and r.bits < expr.bits:
            r = Convert(expr.idx, r.bits, expr.bits, False, r, **expr.tags)

        return r

    def optimize_binaryop(self, expr: BinaryOp):
        if isinstance(expr, BinaryOp) and expr.op == "Shr" and isinstance(expr.operands[1], Const):
            # (N * a) >> M  ==>  a / N1
            inner = expr.operands[0]
            if isinstance(inner, BinaryOp) and inner.op == "Mull" and isinstance(inner.operands[0], Const):
                C = inner.operands[0].value
                X = inner.operands[1]
                V = expr.operands[1].value
                ndigits = 5 if V == 32 else 6
                divisor = self._check_divisor(pow(2, V), C, ndigits)
                if divisor is not None:
                    new_const = Const(None, None, divisor, X.bits)
                    new_div = BinaryOp(inner.idx, "Div", [X, new_const], inner.signed, **inner.tags)
                    return new_div

        elif isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"}:
            expr0, expr1 = expr.operands
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
                            new_const = Const(None, None, divisor, X.bits)
                            new_div = BinaryOp(
                                expr0.operands[0].idx,
                                "Div",
                                [X, new_const],
                                expr0.operands[0].signed,
                                **expr0.operands[0].tags,
                            )
                            # we cannot drop the convert in this case
                            return new_div

        return None

    @staticmethod
    def _check_divisor(a, b, ndigits=6):
        divisor_1 = 1 + (a // b)
        divisor_2 = int(round(a / float(b), ndigits))
        return divisor_1 if divisor_1 == divisor_2 else None
