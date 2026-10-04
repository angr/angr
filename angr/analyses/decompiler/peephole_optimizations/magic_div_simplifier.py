# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

import random

from angr.ailment.expression import BinaryOp, Const, Convert, Expression

from .base import PeepholeOptimizationExprBase

_rng = random.Random(0x6D616769)
_SAMPLES: dict[int, list[int]] = {}


def _samples(n: int) -> list[int]:
    """Signed n-bit test inputs: the extremes, values around zero and multiples of small divisors, plus random ones."""
    if n not in _SAMPLES:
        lo, hi = -(1 << (n - 1)), (1 << (n - 1)) - 1
        vals = set(range(-300, 301))
        vals.update(range(lo, lo + 300))
        vals.update(range(hi - 300, hi + 1))
        vals.update(_rng.randint(lo, hi) for _ in range(500))
        _SAMPLES[n] = sorted(vals)
    return _SAMPLES[n]


def _to_signed(v: int, n: int) -> int:
    v &= (1 << n) - 1
    return v - (1 << n) if v >> (n - 1) else v


def _trunc_div(a: int, d: int) -> int:
    q = abs(a) // abs(d)
    return q if (a >= 0) == (d > 0) else -q


def _is_const(e, value: int | None = None) -> bool:
    return isinstance(e, Const) and isinstance(e.value, int) and (value is None or e.value == value)


class MagicDivisionSimplifier(PeepholeOptimizationExprBase):
    """
    Restore divisions by constants that compilers lower into shifts and multiply-high sequences:

    - ``(x + ((x >>a (n-1)) >> (n-k))) >>a k`` and ``(x + (x >> (n-1))) >>a 1``  =>  ``x /s 2**k``
    - ``x - ((x + <same bias>) & -2**k)``  =>  ``x %s 2**k``
    - ``((x + hi(x * M)) >>a s) - (x >>a (n-1))`` and ``(hi(x * M) >>a s) - (x >>a (n-1))``  =>  ``x /s d``
    - ``hi(x * M) >> s``  =>  ``x /u d``

    where ``hi(x * M)`` is the upper half of a double-width product. Each candidate divisor is checked by evaluating
    the matched sequence on sample inputs.
    """

    __slots__ = ()

    NAME = "Simplify divisions by constants lowered to shifts and multiply-high"
    expr_classes = (BinaryOp, Convert)

    def optimize(self, expr: BinaryOp | Convert, **kwargs):
        if isinstance(expr, Convert):
            return self._match_unsigned(expr, 0)
        if expr.op == "Sar" and _is_const(expr.operands[1]):
            return self._match_signed_pow2(expr)
        if expr.op == "Sub":
            return self._match_signed_pow2_mod(expr) or self._match_signed_magic(expr)
        if expr.op == "Shr" and _is_const(expr.operands[1]):
            return self._match_unsigned(expr.operands[0], expr.operands[1].value_int, expr)
        return None

    def _div(self, expr: Expression, x: Expression, divisor: int, signed: bool) -> Expression:
        r = BinaryOp(
            expr.idx, "Div", [x, Const(self.manager.next_atom(), divisor, x.bits)], signed, bits=x.bits, **expr.tags
        )
        if r.bits != expr.bits:
            r = Convert(self.manager.next_atom(), r.bits, expr.bits, False, r, **expr.tags)
        return r

    # signed division by a power of two

    def _match_signed_pow2(self, expr: BinaryOp):
        k = expr.operands[1].value_int
        add = expr.operands[0]
        if not (isinstance(add, BinaryOp) and add.op == "Add") or k <= 0:
            return None
        n = add.bits
        for x, bias in (add.operands, add.operands[::-1]):
            if x.bits != n or k >= n:
                continue
            if self._is_sign_bias(bias, x, k):
                return self._div(expr, x, 1 << k, True)
        return None

    @staticmethod
    def _is_sign_bias(bias, x: Expression, k: int) -> bool:
        # (x >> (n-1)) for k == 1, ((x >>a (n-1)) >> (n-k)) otherwise
        n = x.bits
        if not (isinstance(bias, BinaryOp) and bias.op == "Shr" and _is_const(bias.operands[1])):
            return False
        shift = bias.operands[1].value_int
        inner = bias.operands[0]
        if k == 1 and shift == n - 1 and inner.likes(x):
            return True
        return (
            shift == n - k
            and isinstance(inner, BinaryOp)
            and inner.op == "Sar"
            and _is_const(inner.operands[1], n - 1)
            and inner.operands[0].likes(x)
        )

    def _match_signed_pow2_mod(self, expr: BinaryOp):
        # x - ((x + bias) & -2**k)  =>  x %s 2**k
        x, masked = expr.operands
        n = expr.bits
        if not (
            isinstance(masked, BinaryOp)
            and masked.op == "And"
            and _is_const(masked.operands[1])
            and isinstance(masked.operands[0], BinaryOp)
            and masked.operands[0].op == "Add"
        ):
            return None
        neg = -masked.operands[1].value_int & ((1 << n) - 1)
        if neg == 0 or neg & (neg - 1):
            return None
        k = neg.bit_length() - 1
        if not 0 < k < n:
            return None
        add = masked.operands[0]
        for a, bias in (add.operands, add.operands[::-1]):
            if a.likes(x) and self._is_sign_bias(bias, x, k):
                return BinaryOp(
                    expr.idx, "Mod", [x, Const(self.manager.next_atom(), 1 << k, n)], True, bits=n, **expr.tags
                )
        return None

    # multiply-high sequences

    @staticmethod
    def _match_hi_mul(e) -> tuple[Expression, int, bool, int] | None:
        """
        Match ``Conv(2n->n, (M * x) >> (n + extra))`` and return (x, M, multiplication is signed, extra).
        """
        if not (isinstance(e, Convert) and e.from_bits == 2 * e.to_bits):
            return None
        n = e.to_bits
        sh = e.operand
        if not (isinstance(sh, BinaryOp) and sh.op in {"Shr", "Sar"} and _is_const(sh.operands[1])):
            return None
        extra = sh.operands[1].value_int - n
        if extra < 0:
            return None
        mul = sh.operands[0]
        if not (isinstance(mul, BinaryOp) and mul.op == "Mull" and mul.bits == 2 * n):
            return None
        a, b = mul.operands
        if _is_const(a) and not _is_const(b):
            m, x = a.value_int, b
        elif _is_const(b) and not _is_const(a):
            m, x = b.value_int, a
        else:
            return None
        if isinstance(x, Convert) and x.from_bits == n and x.to_bits == 2 * n:
            x = x.operand
        if x.bits != n:
            return None
        return x, m, bool(mul.signed), extra

    def _match_signed_magic(self, expr: BinaryOp):
        lhs, rhs = expr.operands
        n = expr.bits
        if not (
            isinstance(rhs, BinaryOp)
            and rhs.op == "Sar"
            and _is_const(rhs.operands[1], n - 1)
            and rhs.operands[0].bits == n
        ):
            return None
        x = rhs.operands[0]

        s = 0
        if isinstance(lhs, BinaryOp) and lhs.op == "Sar" and _is_const(lhs.operands[1]):
            s = lhs.operands[1].value_int
            lhs = lhs.operands[0]
        add_x = False
        hi = self._match_hi_mul(lhs)
        if hi is None and isinstance(lhs, BinaryOp) and lhs.op == "Add":
            for a, b in (lhs.operands, lhs.operands[::-1]):
                if a.likes(x):
                    hi = self._match_hi_mul(b)
                    if hi is not None:
                        add_x = True
                        break
        if hi is None:
            return None
        hx, m, mul_signed, extra = hi
        if not hx.likes(x) or (add_x and extra):
            return None
        s += extra
        mask = (1 << n) - 1
        m_eff = _to_signed(m, n) if mul_signed else m & mask
        m_div = m_eff + (1 << n) if add_x else m_eff
        if m_div <= 0:
            return None
        d = round((1 << (n + s)) / m_div)
        if d < 2:
            return None

        def compute(v: int) -> int:
            h = (v * m_eff) >> n
            t = _to_signed(v + h if add_x else h, n)
            return _to_signed((t >> s) - (v >> (n - 1)), n)

        if all(compute(v) == _trunc_div(v, d) for v in _samples(n)):
            return self._div(expr, x, d, True)
        return None

    def _match_unsigned(self, e, s: int, root: Expression | None = None):
        hi = self._match_hi_mul(e)
        if hi is None:
            return None
        x, m, mul_signed, extra = hi
        if mul_signed:
            return None
        n = x.bits
        s += extra
        m &= (1 << n) - 1
        if m == 0:
            return None
        d = round((1 << (n + s)) / m)
        if d < 2:
            return None
        mask = (1 << n) - 1
        if all(((v & mask) * m) >> (n + s) == (v & mask) // d for v in _samples(n)):
            return self._div(root if root is not None else e, x, d, False)
        return None
