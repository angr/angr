from ailment.expression import Convert, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ConvShlShr(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "(expr << P) >> Q => (expr & mask) >> R"
    expr_classes = (BinaryOp, )  # all expressions are allowed

    def optimize(self, expr: BinaryOp):

        # (Conv(M->N, expr) << P) >> Q  ==>  (Conv(M->N, expr) & bitmask) >> (Q-P), where
        #       Q >= P, and
        #       M < N, and
        #       bitmask = 0b('1' * (N - P))
        if expr.op == "Shr" and isinstance(expr.operands[1], Const):
            q = expr.operands[1].value
            expr_b = expr.operands[0]
            if isinstance(expr_b, BinaryOp) and expr_b.op == "Shl" and isinstance(expr_b.operands[1], Const):
                p = expr_b.operands[1].value
                expr_a = expr_b.operands[0]
                if q >= p and isinstance(expr_a, Convert) and not expr_a.is_signed:
                    m = expr_a.from_bits
                    n = expr_a.to_bits
                    if m < n and n >= p:
                        bitmask = (1 << (n - p)) - 1
                        and_expr = BinaryOp(
                            None,
                            'And',
                            (
                                Convert(expr_a.idx, m, n, False, expr_a.operand, **expr_a.tags),
                                Const(None, None, bitmask, n),
                            ),
                            False,
                            variable=None,
                            variable_offset=None,
                            **expr.tags,
                        )
                        return BinaryOp(
                            None,
                            'Shr',
                            (
                                and_expr,
                                Const(None, None, q - p, and_expr.bits),
                            ),
                            False,
                            **expr.tags,
                        )

        return None
