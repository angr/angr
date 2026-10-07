from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Expression
from angr.analyses.decompiler.block_walkers import HasCallExprWalker, HasCallNotification

from .base import PeepholeOptimizationExprBase

_HAS_CALL_WALKER = HasCallExprWalker()


def _has_call(expr: Expression) -> bool:
    try:
        _HAS_CALL_WALKER.walk_expression(expr)
    except HasCallNotification:
        return True
    return False


class RecombineSplitHalves(PeepholeOptimizationExprBase):
    """
    (a & (2 ** N - 1)) | ((a >> N) << N)  =>  a

    A value split into register halves (e.g., rdtsc's edx:eax) and put back together. The left shift may already be
    rewritten into a multiplication, and the low half may be a pair of truncating and extending conversions.
    """

    __slots__ = ()

    NAME = "(a & mask) | ((a >> N) << N) => a"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in ("Or", "Add") or len(expr.operands) != 2:
            return None
        for lo, hi in (expr.operands, expr.operands[::-1]):
            hi_info = self._high_half(hi)
            if hi_info is None:
                continue
            a, n = hi_info
            # a occurs twice; folding two calls into one would drop a side effect
            if a.bits == expr.bits and self._is_low_half(lo, a, n) and not _has_call(a):
                return a
        return None

    @staticmethod
    def _high_half(expr: Expression) -> tuple[Expression, int] | None:
        """Match (a >> N) << N or (a >> N) * 2 ** N; return (a, N)."""
        if not (isinstance(expr, BinaryOp) and isinstance(expr.operands[1], Const)):
            return None
        amount = expr.operands[1].value
        if not isinstance(amount, int) or amount <= 0:
            return None
        if expr.op == "Shl":
            n = amount
        elif expr.op == "Mul" and amount & (amount - 1) == 0:
            n = amount.bit_length() - 1
        else:
            return None
        inner = expr.operands[0]
        if (
            isinstance(inner, BinaryOp)
            and inner.op == "Shr"
            and isinstance(inner.operands[1], Const)
            and inner.operands[1].value == n
            and 0 < n < inner.bits
        ):
            return inner.operands[0], n
        return None

    @staticmethod
    def _is_low_half(expr: Expression, a: Expression, n: int) -> bool:
        if (
            isinstance(expr, BinaryOp)
            and expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == (1 << n) - 1
        ):
            return expr.operands[0].likes(a)
        # Conv(N->M, Conv(M->N, a))
        return (
            isinstance(expr, Convert)
            and not expr.is_signed
            and expr.from_bits == n
            and isinstance(expr.operand, Convert)
            and expr.operand.from_bits == a.bits
            and expr.operand.to_bits == n
            and expr.operand.operand.likes(a)
        )
