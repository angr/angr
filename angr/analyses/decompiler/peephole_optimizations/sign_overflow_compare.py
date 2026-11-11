from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase

_COMMUTATIVE = frozenset({"Add", "And", "Or", "Xor", "Mul", "CmpEQ", "CmpNE", "LogicalAnd", "LogicalOr"})
_MIRROR = {"CmpLT": "CmpGT", "CmpGT": "CmpLT", "CmpLE": "CmpGE", "CmpGE": "CmpLE"}
_NEGATED = {"CmpLT": "CmpGE", "CmpGE": "CmpLT", "CmpLE": "CmpGT", "CmpGT": "CmpLE"}


def _same(a: Expression, b: Expression) -> bool:
    """likes(), except that the floating-point marker of an integer complement does not matter"""
    if a.likes(b):
        return True
    if a.bits != b.bits:
        return False
    if isinstance(a, UnaryOp) and isinstance(b, UnaryOp):
        return a.op == b.op == "BitwiseNeg" and _same(a.operand, b.operand)
    if isinstance(a, Convert) and isinstance(b, Convert):
        return (
            a.from_bits == b.from_bits
            and a.is_signed == b.is_signed
            and a.from_type == b.from_type
            and a.to_type == b.to_type
            and _same(a.operand, b.operand)
        )
    if isinstance(a, BinaryOp) and isinstance(b, BinaryOp):
        if a.op != b.op or a.signed != b.signed or a.floating_point != b.floating_point:
            return False
        a0, a1 = a.operands
        b0, b1 = b.operands
        if _same(a0, b0) and _same(a1, b1):
            return True
        return a.op in _COMMUTATIVE and _same(a0, b1) and _same(a1, b0)
    return False


def _const(e: Expression) -> int | None:
    return e.value_int if isinstance(e, Const) and isinstance(e.value, int) else None


def _strip(e: Expression) -> Expression:
    """a & a ==> a"""
    while isinstance(e, BinaryOp) and e.op in ("And", "Or") and _same(*e.operands):
        e = e.operands[0]
    return e


def _complemented(e: Expression) -> Expression | None:
    """x when e is ~x"""
    e = _strip(e)
    if isinstance(e, UnaryOp) and e.op == "BitwiseNeg" and e.operand.bits == e.bits:
        return _strip(e.operand)
    if isinstance(e, BinaryOp) and e.op == "Xor":
        for i in (0, 1):
            if _const(e.operands[i]) == (1 << e.bits) - 1:
                return _strip(e.operands[1 - i])
    return None


def _xor(e: Expression) -> tuple[Expression, Expression] | None:
    e = _strip(e)
    if isinstance(e, BinaryOp) and e.op == "Xor" and e.operands[0].bits == e.operands[1].bits == e.bits:
        return e.operands[0], e.operands[1]
    return None


class _Linear:
    """An expression as constant + sum of coefficient * term, modulo 2**bits."""

    __slots__ = ("bits", "const", "terms")

    def __init__(self, bits: int, const: int = 0, terms: list[tuple[Expression, int]] | None = None):
        self.bits = bits
        self.const = const & ((1 << bits) - 1)
        self.terms = terms or []

    @staticmethod
    def of(e: Expression) -> _Linear:
        e = _strip(e)
        bits = e.bits
        c = _const(e)
        if c is not None:
            return _Linear(bits, c)
        inner = _complemented(e)
        if inner is not None:
            # ~x == -x - 1
            return _Linear.of(inner).scaled(-1).plus(_Linear(bits, -1))
        if isinstance(e, UnaryOp) and e.op == "Neg" and not e.floating_point and e.operand.bits == bits:
            return _Linear.of(e.operand).scaled(-1)
        if isinstance(e, BinaryOp) and not e.floating_point and e.operands[0].bits == e.operands[1].bits == bits:
            if e.op in ("Add", "Sub"):
                rhs = _Linear.of(e.operands[1])
                return _Linear.of(e.operands[0]).plus(rhs if e.op == "Add" else rhs.scaled(-1))
            if e.op == "Mul":
                for i in (0, 1):
                    c = _const(e.operands[i])
                    if c is not None:
                        return _Linear.of(e.operands[1 - i]).scaled(c)
        return _Linear(bits, 0, [(e, 1)])

    def scaled(self, k: int) -> _Linear:
        mask = (1 << self.bits) - 1
        return _Linear(self.bits, self.const * k, [(t, c * k & mask) for t, c in self.terms if c * k & mask])

    def plus(self, other: _Linear) -> _Linear:
        mask = (1 << self.bits) - 1
        terms = list(self.terms)
        for t, c in other.terms:
            for i, (t0, c0) in enumerate(terms):
                if _same(t0, t):
                    terms[i] = (t0, (c0 + c) & mask)
                    break
            else:
                terms.append((t, c))
        return _Linear(self.bits, self.const + other.const, [(t, c) for t, c in terms if c])

    def minus(self, other: _Linear) -> _Linear:
        return self.plus(other.scaled(-1))

    def complement(self) -> _Linear:
        return self.scaled(-1).plus(_Linear(self.bits, -1))

    def is_zero(self) -> bool:
        return self.const == 0 and not self.terms

    def equals(self, other: _Linear) -> bool:
        return self.bits == other.bits and self.minus(other).is_zero()


def _sign_test(e: Expression) -> tuple[Expression, bool] | None:
    """(w, False) when e is ``w <s 0`` or ``w <=s -1``, (w, True) when e is ``w >=s 0`` or ``w >s -1``"""
    if not (isinstance(e, BinaryOp) and e.signed and not e.floating_point):
        return None
    w, c = e.operands
    if e.op in ("CmpLT", "CmpGE") and _const(c) == 0:
        return w, e.op == "CmpGE"
    if e.op in ("CmpLE", "CmpGT") and _const(c) == (1 << c.bits) - 1:
        return w, e.op == "CmpGT"
    return None


def _sign_xor(e: BinaryOp) -> tuple[Expression, Expression, bool] | None:
    """(v, w, negated) when e is ``(v <s 0) != (w <s 0)``, or its negation"""
    if e.floating_point:
        return None
    if e.op in ("CmpNE", "CmpEQ", "Xor") and e.bits == 1:
        p, q = _sign_test(e.operands[0]), _sign_test(e.operands[1])
        if p is None or q is None:
            return None
        return p[0], q[0], p[1] ^ q[1] ^ (e.op == "CmpEQ")
    # (p || q) && (!p || !q) is p != q; (p && q) || (!p && !q) is p == q
    inner = {"LogicalAnd": "LogicalOr", "LogicalOr": "LogicalAnd"}.get(e.op)
    if inner is None:
        return None
    tests = []
    for half in e.operands:
        if not (isinstance(half, BinaryOp) and half.op == inner):
            return None
        p, q = _sign_test(half.operands[0]), _sign_test(half.operands[1])
        if p is None or q is None:
            return None
        tests.append((p, q))
    (p0, q0), (p1, q1) = tests
    if not (_same(p0[0], p1[0]) and _same(q0[0], q1[0])):
        p1, q1 = q1, p1
    if not (_same(p0[0], p1[0]) and _same(q0[0], q1[0])) or p0[1] == p1[1] or q0[1] == q1[1]:
        return None
    return p0[0], q0[0], p0[1] ^ q0[1] ^ (e.op == "LogicalOr")


class SignOverflowCompare(PeepholeOptimizationExprBase):
    """
    The x86 "less" condition, SF != OF, spelled over a subtraction or an addition, is one signed comparison::

        ((a - b) <s 0) != (((a ^ b) & (a ^ (a - b))) <s 0)  ==>  a <s b
        ((a + ~b) <s 0) != (((a ^ b) & (a ^ (a + ~b))) <s 0)  ==>  a <=s b

    ``==``, or the complemented result (``~(~a + b)`` is how a NOR-based VM subtracts), gives the negation. The
    operands' sign difference may be written ``~(x ^ y)``, the result in any linear form, a sign test as ``>= 0`` and
    the inequality as ``(p || q) && (!p || !q)``.
    """

    __slots__ = ()

    NAME = "SF != OF => signed comparison"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        signs = _sign_xor(expr)
        if signs is None or signs[0].bits != signs[1].bits:
            return None
        for r, ov in (signs[:2], signs[1::-1]):
            hit = self._less(_Linear.of(r), ov)
            if hit is not None:
                op, a, b = hit
                return self._cmp(_NEGATED[op] if signs[2] else op, a, b, expr)
        return None

    def _less(self, res: _Linear, ov: Expression) -> tuple[str, Expression, Expression] | None:
        """(op, a, b): ``sign(res) != sign(ov)`` is ``a op b`` when ov is the overflow of the operation computing res"""
        ov = _strip(ov)
        if not (isinstance(ov, BinaryOp) and ov.op == "And" and ov.operands[0].bits == ov.operands[1].bits):
            return None
        for p, q in (ov.operands, ov.operands[::-1]):
            # q: an operand ^ the result; p: the operands differ in sign
            qq = _xor(q)
            if qq is None:
                continue
            differ = _xor(p)
            if differ is None:
                inner = _complemented(p)
                same_sign = None if inner is None else _xor(inner)
                if same_sign is None:
                    continue
                x, y = same_sign
                if _const(x) is not None or (_complemented(x) is not None and _const(y) is None):
                    x, y = y, x
                differ = x, self._complement(y)
            for a, b in (differ, differ[::-1]):
                la, lb = _Linear.of(a), _Linear.of(b)
                for operand, result in (qq, qq[::-1]):
                    lo, lr = _Linear.of(operand), _Linear.of(result)
                    # a - b, overflowing when a's sign differs from b's and the result's
                    if lr.equals(la.minus(lb)) and lo.equals(la):
                        op = "CmpLT"
                    # a + ~b, the true sum is negative iff a <= b
                    elif lr.equals(la.plus(lb.complement())) and (lo.equals(la) or lo.equals(lb.complement())):
                        op = "CmpLE"
                    else:
                        continue
                    if res.equals(lr):
                        return op, a, b
                    if res.equals(lr.complement()):
                        return _NEGATED[op], a, b
        return None

    def _complement(self, x: Expression) -> Expression:
        c = _const(x)
        if c is not None:
            return Const(self.manager.next_atom(), ~c & ((1 << x.bits) - 1), x.bits, **x.tags)
        inner = _complemented(x)
        if inner is not None:
            return inner
        return UnaryOp(self.manager.next_atom(), "BitwiseNeg", x, bits=x.bits, **x.tags)

    def _cmp(self, op: str, a: Expression, b: Expression, expr: BinaryOp) -> BinaryOp:
        # ~a op ~b is b op a
        if (_complemented(a) is not None or _complemented(b) is not None) and all(
            _const(e) is not None or _complemented(e) is not None for e in (a, b)
        ):
            a, b = self._complement(b), self._complement(a)
        if _const(a) is not None:
            op, a, b = _MIRROR[op], b, a
        return BinaryOp(expr.idx, op, [a, b], True, bits=1, **expr.tags)


class OrderedOrEqual(PeepholeOptimizationExprBase):
    """
    ``(a < b) || (a == b)`` ==> ``a <= b`` and ``(a >= b) && (a != b)`` ==> ``a > b``, signed or unsigned, with the
    equality in any linear spelling (``a - b == 0``, ``~(~a + b) == 0``) or as ``a ^ b == 0``.
    """

    __slots__ = ()

    NAME = "(a < b) || (a == b) => a <= b"
    expr_classes = (BinaryOp,)

    _RULES = {
        "LogicalOr": ("CmpEQ", {"CmpLT": "CmpLE", "CmpGT": "CmpGE"}),
        "LogicalAnd": ("CmpNE", {"CmpGE": "CmpGT", "CmpLE": "CmpLT"}),
    }

    def optimize(self, expr: BinaryOp, **kwargs):
        rule = self._RULES.get(expr.op)
        if rule is None:
            return None
        eq_op, merged = rule
        for i in (0, 1):
            order, eq = expr.operands[i], expr.operands[1 - i]
            if not (isinstance(order, BinaryOp) and order.op in merged and not order.floating_point):
                continue
            if not (isinstance(eq, BinaryOp) and eq.op == eq_op and not eq.floating_point):
                continue
            a, b = order.operands
            p, q = eq.operands
            if not a.bits == b.bits == p.bits == q.bits:
                continue
            xored = _xor(p) if _const(q) == 0 else _xor(q) if _const(p) == 0 else None
            if xored is not None:
                p, q = xored
            # p == q iff a == b when p - q is a - b or b - a
            want = _Linear.of(a).minus(_Linear.of(b))
            diff = _Linear.of(p).minus(_Linear.of(q))
            if diff.equals(want) or diff.equals(want.scaled(-1)):
                return BinaryOp(expr.idx, merged[order.op], [a, b], order.signed, bits=order.bits, **order.tags)
        return None


class ComplementCompare(PeepholeOptimizationExprBase):
    """
    ``~a < ~b`` ==> ``b < a`` and ``~a < C`` ==> ``a > ~C``, for every ordered comparison, signed or unsigned: the
    complement reverses both orders.
    """

    __slots__ = ()

    NAME = "~a < ~b => b < a"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in _MIRROR or expr.floating_point:
            return None
        a, b = expr.operands
        if a.bits != b.bits:
            return None
        flipped = []
        for e in (a, b):
            c = _const(e)
            inner = _complemented(e)
            if c is not None:
                flipped.append(Const(self.manager.next_atom(), ~c & ((1 << e.bits) - 1), e.bits, **e.tags))
            elif inner is not None:
                flipped.append(inner)
            else:
                return None
        if _const(a) is not None and _const(b) is not None:
            return None
        return BinaryOp(expr.idx, _MIRROR[expr.op], flipped, expr.signed, bits=expr.bits, **expr.tags)
