import math

from ailment.expression import Convert, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ConvConstMullAShift(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Conv(64->32, (N * a) >> 32) => a / N1"
    expr_classes = (Convert, )

    def optimize(self, expr: Convert):

        if expr.from_bits == 64 and expr.to_bits == 32 \
                and isinstance(expr.operand, BinaryOp) and expr.operand.op == "Shr" \
                and isinstance(expr.operand.operands[1], Const) \
                and expr.operand.operands[1].value == 32:

            inner = expr.operand.operands[0]
            if isinstance(inner, BinaryOp) and inner.op == "Mull" and isinstance(inner.operands[0], Const):
                bits = 32
                C = inner.operands[0].value
                X = inner.operands[1]
                V = bits
                ndigits = 5 if V == 32 else 6
                divisor = self._check_divisor(pow(2, V), C, ndigits)
                if divisor is not None:
                    new_const = Const(None, None, divisor, V)
                    new_expr = BinaryOp(inner.idx, 'Div', [X, new_const], inner.signed, **inner.tags)
                    return new_expr

    @staticmethod
    def _check_divisor(a, b, ndigits=6):
        divisor_1 = 1 + (a//b)
        divisor_2 = int(round(a/float(b), ndigits))
        return divisor_1 if divisor_1 == divisor_2 else None
