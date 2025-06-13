# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
import math

from angr.ailment.expression import Convert, BinaryOp, Const, Expression

from .base import PeepholeOptimizationExprBase


class OptimizedDivisionSimplifier(PeepholeOptimizationExprBase):
    """
    Convert expressions with right shifts into expressions with divisions.
    """

    __slots__ = ()

    NAME = "Simplify optimized division expressions, e.g., (N * a) >> M => a / N1"
    expr_classes = (Convert, BinaryOp)

    def optimize(  # pylint:disable=unused-argument
        self, expr: Convert | BinaryOp, stmt_idx: int | None = None, block=None, **kwargs
    ):
        r = None

        if isinstance(expr, Convert):
            if expr.from_bits == 64 and expr.to_bits == 32 and isinstance(expr.operand, BinaryOp):
                r = self.optimize_binaryop(expr.operand)

        elif isinstance(expr, BinaryOp):
            r = self.optimize_binaryop(expr)

        # keep size
        if r is not None and r.bits < expr.bits:
            r = Convert(expr.idx, r.bits, expr.bits, False, r, **expr.tags)

        return r

    def optimize_binaryop(self, original_expr: BinaryOp):
        if isinstance(original_expr, BinaryOp):
            # try to unify if both operands are wrapped with Convert()
            conv_expr = self._unify_conversion(original_expr)
            expr = original_expr if conv_expr is None else conv_expr.operand
            assert isinstance(expr, BinaryOp)

            if expr.op == "Shr" and isinstance(expr.operands[1], Const):
                r = self._match_case_b(expr)
                if r is not None:
                    return self._reconvert(r, conv_expr) if conv_expr is not None else r
                assert isinstance(expr.operands[1].value, int)
                r = self._match_case_c(expr.operands[0], expr.operands[1].value)
                if r is not None:
                    return self._reconvert(r, conv_expr) if conv_expr is not None else r

            elif expr.op in {"Add", "Sub"}:
                expr0, expr1 = expr.operands
                if isinstance(expr1, Convert) and expr1.from_bits == 32 and expr1.to_bits == 64:
                    r = self._match_case_a(expr0, expr1)
                    if r is not None:
                        return self._reconvert(r, conv_expr) if conv_expr is not None else r

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
                            r = BinaryOp(
                                expr0_operand.idx,
                                "Div",
                                [X, new_const],
                                expr0_operand.signed,
                                **expr0_operand.tags,
                            )
                            return self._reconvert(r, conv_expr) if conv_expr is not None else r

        return None

    def _match_case_a(self, expr0: Expression, expr1: Convert) -> BinaryOp | None:
        # (
        #   (((Conv(32->64, vvar_44{reg 32}) * 0x4325c53f<64>) >>a 0x24<8>) & 0xffffffff<64>) -
        #   Conv(32->s64, (vvar_44{reg 32} >>a 0x1f<8>))
        # )

        expr1_op = expr1.operand

        if (
            isinstance(expr0, BinaryOp)
            and expr0.op == "And"
            and isinstance(expr0.operands[1], Const)
            and expr0.operands[1].value == 0xFFFFFFFF
        ):
            expr0 = expr0.operands[0]
        else:
            return None

        if (
            isinstance(expr0, BinaryOp)
            and expr0.op in {"Shr", "Sar"}
            and isinstance(expr0.operands[1], Const)
            and isinstance(expr1_op, BinaryOp)
            and expr1_op.op in {"Shr", "Sar"}
            and isinstance(expr1_op.operands[1], Const)
        ):
            if (
                isinstance(expr0.operands[0], BinaryOp)
                and expr0.operands[0].op in {"Mull", "Mul"}
                and isinstance(expr0.operands[0].operands[1], Const)
            ):
                a0 = expr0.operands[0].operands[0]
                a1 = expr1_op.operands[0]
            elif (
                isinstance(expr1_op.operands[0], BinaryOp)
                and expr1_op.operands[0].op in {"Mull", "Mul"}
                and isinstance(expr1_op.operands[0].operands[1], Const)
            ):
                a1 = expr0.operands[0].operands[0]
                a0 = expr1_op.operands[0]
            else:
                a0, a1 = None, None

            # a0: Conv(32->64, vvar_44{reg 32})
            # a1: vvar_44{reg 32}
            if isinstance(a0, Convert) and a1 is not None and a0.from_bits == a1.bits:
                a0 = a0.operand

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

        return None

    @staticmethod
    def _match_case_b(expr: BinaryOp) -> BinaryOp | Convert | None:
        """
        A more complex (but general) case for unsigned 32-bit division by a constant integer.

        Ref: https://ridiculousfish.com/blog/posts/labor-of-division-episode-i.html

        Given n and d, n//d (unsigned) can be rewritten to t >> (p - 1) where
        - p = ceiling(log2(d))
        - m = ceiling((2 ** (32 + p) / d))
        - q = (m * n) >> 32
        - t = q + ((n - q) >> 1)

        We can match the expression against  t >> (p - 1).
        """

        # t >> (p - 1)
        if not (isinstance(expr, BinaryOp) and expr.op == "Shr"):
            return None
        if not (isinstance(expr.operands[1], Const) and expr.operands[1].value > 0):
            return None
        p_minus_1 = expr.operands[1].value
        p = p_minus_1 + 1
        t = expr.operands[0]

        # unmask
        if isinstance(t, BinaryOp) and t.op == "And":
            if isinstance(t.operands[1], Const) and t.operands[1].value == 0xFFFFFFFF:
                t = t.operands[0]
            elif isinstance(t.operands[0], Const) and t.operands[0].value == 0xFFFFFFFF:
                t = t.operands[1]
            else:
                return None

        # t = q + ((n - q) >> 1)
        if not (isinstance(t, BinaryOp) and t.op == "Add"):
            return None

        if (
            isinstance(t.operands[0], BinaryOp)
            and t.operands[0].op == "Shr"
            and isinstance(t.operands[0].operands[1], Const)
            and t.operands[0].operands[1].value == 1
        ):
            q = t.operands[1]
            n_minus_q = t.operands[0].operands[0]
        elif (
            isinstance(t.operands[1], BinaryOp)
            and t.operands[1].op == "Shr"
            and isinstance(t.operands[1].operands[1], Const)
            and t.operands[1].operands[1].value == 1
        ):
            q = t.operands[0]
            n_minus_q = t.operands[1]
        else:
            return None
        if isinstance(q, Convert) and q.from_bits == 64 and q.to_bits == 32:
            q = q.operand
        if isinstance(n_minus_q, Convert) and n_minus_q.from_bits == 64 and n_minus_q.to_bits == 32:
            n_minus_q = n_minus_q.operand

        # unmask
        if isinstance(n_minus_q, BinaryOp) and n_minus_q.op == "And":
            if isinstance(n_minus_q.operands[1], Const) and n_minus_q.operands[1].value == 0xFFFFFFFF:
                n_minus_q = n_minus_q.operands[0]
            elif isinstance(n_minus_q.operands[0], Const) and n_minus_q.operands[0].value == 0xFFFFFFFF:
                n_minus_q = n_minus_q.operands[1]
            else:
                return None

        if not (isinstance(n_minus_q, BinaryOp) and n_minus_q.op == "Sub"):
            return None
        if not q.likes(n_minus_q.operands[1]):
            return None

        # q = (m * n) >> 32
        if not (
            isinstance(q, BinaryOp) and q.op == "Shr" and isinstance(q.operands[1], Const) and q.operands[1].value == 32
        ):
            return None
        if not (isinstance(q.operands[0], BinaryOp) and q.operands[0].op in {"Mull", "Mul"}):
            return None
        if isinstance(q.operands[0].operands[1], Const):
            n = q.operands[0].operands[0]
            m = q.operands[0].operands[1].value
        elif isinstance(q.operands[0].operands[0], Const):
            n = q.operands[0].operands[1]
            m = q.operands[0].operands[0].value
        else:
            # this should never happen, because multiplication of two constants are eagerly evaluated
            return None

        assert isinstance(m, int) and isinstance(p, int)
        divisor = math.ceil((2 ** (32 + p)) / (m + 0x1_0000_0000))
        if divisor == 0:
            return None
        divisor_expr = Const(None, None, divisor, n.bits)
        div = BinaryOp(expr.idx, "Div", [n, divisor_expr], signed=False, **expr.tags)
        if expr.bits != div.bits:
            div = Convert(expr.idx, div.bits, expr.bits, False, div, **expr.tags)
        return div

    def _match_case_c(self, inner, m: int) -> BinaryOp | None:
        # (N * a) >> M  ==>  a / N1
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
                V = m
                ndigits = 5 if V == 32 else 6
                divisor = self._check_divisor(pow(2, V), C, ndigits)
                if divisor is not None:
                    new_const = Const(None, None, divisor, X.bits)
                    return BinaryOp(inner.idx, "Div", [X, new_const], inner.signed, **inner.tags)
        return None

    @staticmethod
    def _check_divisor(a, b, ndigits=6):
        if b == 0:
            return None
        divisor_1 = 1 + (a // b)
        divisor_2 = int(round(a / float(b), ndigits))
        return divisor_1 if divisor_1 == divisor_2 else None

    @staticmethod
    def _unify_conversion(expr: BinaryOp) -> Convert | None:
        if (
            isinstance(expr.operands[0], Convert)
            and isinstance(expr.operands[1], Convert)
            and expr.operands[1].to_bits == expr.operands[0].to_bits
            and expr.operands[1].from_bits == expr.operands[0].from_bits
            and expr.op in {"Add", "Sub"}
        ):
            op0 = expr.operands[0]
            op0_inner = expr.operands[0].operand
            # op1 = expr.operands[1]
            op1_inner = expr.operands[1].operand

            new_expr = BinaryOp(
                expr.idx,
                expr.op,
                (op0_inner, op1_inner),
                expr.signed,
                bits=op0.from_bits,
                **expr.tags,
            )
            return Convert(
                op0.idx,
                op0.from_bits,
                op0.to_bits,
                op0.is_signed,
                new_expr,
                **op0.tags,
            )
        return None

    @staticmethod
    def _reconvert(expr: Expression, conv: Convert) -> Convert:
        return Convert(
            conv.idx,
            conv.from_bits,
            conv.to_bits,
            conv.is_signed,
            expr,
            from_type=conv.from_type,
            to_type=conv.to_type,
            rounding_mode=conv.rounding_mode,
            **conv.tags,
        )
