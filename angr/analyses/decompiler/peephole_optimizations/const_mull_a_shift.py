# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

from ailment.expression import Convert, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ConstMullAShift(PeepholeOptimizationExprBase):
    """
    Convert expressions with right shifts into expressions with divisions.
    """

    __slots__ = ()

    NAME = "Conv(64->32, (N * a) >> M) => a / N1"
    expr_classes = (Convert, BinaryOp)

    def optimize(self, expr: Convert | BinaryOp, **kwargs):
        r = None

        if isinstance(expr, Convert):
            if expr.from_bits == 64 and expr.to_bits == 32:
                r = self.optimize_binaryop(expr.operand)

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
            if isinstance(inner, BinaryOp) and inner.op in {"Mull", "Mul"} and not inner.signed:
                if isinstance(inner.operands[0], Const) and not isinstance(inner.operands[1], Const):
                    C = inner.operands[0].value
                    X = inner.operands[1]
                elif isinstance(inner.operands[1], Const) and not isinstance(inner.operands[0], Const):
                    C = inner.operands[1].value
                    X = inner.operands[0]
                else:
                    C = X = None

                if C is not None and X is not None:
                    V = expr.operands[1].value
                    ndigits = 5 if V == 32 else 6
                    divisor = self._check_divisor(pow(2, V), C, ndigits)
                    if divisor is not None:
                        new_const = Const(None, None, divisor, X.bits)
                        return BinaryOp(inner.idx, "Div", [X, new_const], inner.signed, **inner.tags)

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
                elif (
                    isinstance(expr1.operands[0], BinaryOp)
                    and expr1.operands[0].op in {"Mull", "Mul"}
                    and isinstance(expr1.operands[0].operands[1], Const)
                ):
                    a1 = expr0.operands[0].operands[0]
                    a0 = expr1.operands[0]
                else:
                    a0, a1 = None, None
                if a0 is not None and a1 is not None and a0.likes(a1):
                    # (a * x >> M1) +/- (a >> M2)  ==>  a / N
                    C = expr0.operands[0].operands[1].value
                    X = a0
                    V = expr0.operands[1].value
                    ndigits = 5 if V == 32 else 6
                    divisor = self._check_divisor(pow(2, V), C, ndigits)
                    if divisor is not None:
                        new_const = Const(None, None, divisor, X.bits)
                        # we cannot drop the convert in this case
                        return BinaryOp(
                            expr0.operands[0].idx,
                            "Div",
                            [X, new_const],
                            expr0.operands[0].signed,
                            **expr0.operands[0].tags,
                        )

            # with Convert in consideration
            if (
                isinstance(expr0, BinaryOp)
                and expr0.op in {"Shr", "Sar"}
                and isinstance(expr0.operands[1], Const)
                and expr0.operands[1].value == 0x3F
                and isinstance(expr1, BinaryOp)
                and expr1.op in {"Shr", "Sar"}
                and isinstance(expr1.operands[1], Const)
                and expr1.operands[1].value == 0x20
            ):
                expr0_operand = expr0.operands[0]
                expr1_operand = expr1.operands[0]
                if (
                    isinstance(expr0_operand, BinaryOp)
                    and expr0_operand.op in {"Mull", "Mul"}
                    and expr0_operand.signed
                    and isinstance(expr0_operand.operands[1], Const)
                ):
                    a0 = expr0_operand.operands[0]
                    a1 = expr1_operand.operands[0]
                elif (
                    isinstance(expr1_operand, BinaryOp)
                    and expr1_operand.op in {"Mull", "Mul"}
                    and expr1_operand.signed
                    and isinstance(expr1_operand.operands[1], Const)
                ):
                    a0 = expr1_operand.operands[0]
                    a1 = expr0_operand.operands[0]
                else:
                    a0, a1 = None, None

                if a0 is not None and a1 is not None and a0.likes(a1):
                    # (a * x >> 0x3f) +/- (a * x >> 0x20)  ==>  a / N
                    C = expr0_operand.operands[1].value
                    X = a0
                    V = 32
                    ndigits = 5 if V == 32 else 6
                    divisor = self._check_divisor(pow(2, V), C, ndigits)
                    if divisor is not None:
                        new_const = Const(None, None, divisor, X.bits)
                        return BinaryOp(
                            expr0_operand.idx,
                            "Div",
                            [X, new_const],
                            expr0_operand.signed,
                            **expr0_operand.tags,
                        )

        return None

    @staticmethod
    def _check_divisor(a, b, ndigits=6):
        divisor_1 = 1 + (a // b)
        divisor_2 = int(round(a / float(b), ndigits))
        return divisor_1 if divisor_1 == divisor_2 else None
