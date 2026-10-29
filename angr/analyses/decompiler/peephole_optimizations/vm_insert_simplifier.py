from __future__ import annotations

import itertools

import archinfo

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Extract, Insert, UnaryOp

from .base import PeepholeOptimizationExprBase
from .known_bits import block_defs_resolver, known_bits
from .masked_insert import _extract_shift, _insert_shift, _visibly_fp

_MAX_SCALAR_BITS = 64
_MAX_DEPTH = 12
# free constants in a lifted bitwise tree; the identity search is exponential in it
_MAX_FREE = 6


def _mask(bits: int) -> int:
    return (1 << bits) - 1


def _is_int_convert(expr: Expression) -> bool:
    return (
        isinstance(expr, Convert) and expr.from_type == Convert.TYPE_INT and expr.to_type == Convert.TYPE_INT
    )


def _const_int(expr: Expression) -> int | None:
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return expr.value_int
    return None


class _Lifter:
    """
    Lifts ``v``, a bitwise function of ``L`` (bits [shift, shift + v.bits) of ``base``) and other values, to the full
    width of ``base``: ``L`` becomes ``base``, every other value ``t`` becomes ``zext(t) << shift`` and every constant
    and complement gets free bits outside the hole. The lifted tree equals ``Insert(base, shift, v)`` when, with those
    free bits chosen, it is the identity on ``base`` outside the hole.
    """

    def __init__(self, opt: PeepholeOptimizationExprBase, base: Expression, shift: int, width: int, low: Expression):
        self.opt = opt
        self.base = base
        self.shift = shift
        self.width = width
        self.low = low
        self.bits = base.bits
        self.free = 0
        self.uses_low = False

    def scan(self, v: Expression, depth: int = 0):
        """A skeleton: ("L",), ("T", expr), ("C", value), ("N", child), (op, a, b)."""
        if depth > _MAX_DEPTH:
            return None
        if v.bits == self.width and self.opt.is_part(v, self.low):
            self.uses_low = True
            return ("L",)
        c = _const_int(v)
        if c is not None:
            self.free += 1
            return ("C", c & _mask(self.width))
        if isinstance(v, UnaryOp) and v.op == "BitwiseNeg" and v.bits == self.width:
            child = self.scan(v.operand, depth + 1)
            if child is None:
                return None
            self.free += 1
            return ("N", child)
        if (
            isinstance(v, BinaryOp)
            and v.op in {"And", "Or", "Xor"}
            and not v.floating_point
            and v.operands[0].bits == v.operands[1].bits == self.width
        ):
            a = self.scan(v.operands[0], depth + 1)
            b = self.scan(v.operands[1], depth + 1)
            if a is None or b is None:
                return None
            return (v.op, a, b)
        if _visibly_fp(v):
            return None
        return ("T", v)

    @staticmethod
    def _eval(node, x: int, choice: list[int]) -> int:
        """Evaluate one bit outside the hole: L is x, other values are 0, free bits come from ``choice``."""
        kind = node[0]
        if kind == "L":
            return x
        if kind == "T":
            return 0
        if kind == "C":
            return choice.pop()
        if kind == "N":
            child = _Lifter._eval(node[1], x, choice)
            return child ^ choice.pop()
        a = _Lifter._eval(node[1], x, choice)
        b = _Lifter._eval(node[2], x, choice)
        return {"And": a & b, "Or": a | b, "Xor": a ^ b}[kind]

    def solve(self, skeleton) -> list[int] | None:
        for bits in itertools.product((0, 1), repeat=self.free):
            if all(self._eval(skeleton, x, list(bits)) == x for x in (0, 1)):
                return list(bits)
        return None

    def build(self, node, choice: list[int]) -> Expression:
        m = self.opt.manager
        full = _mask(self.bits)
        hole = _mask(self.width) << self.shift
        kind = node[0]
        if kind == "L":
            return self.base
        if kind == "T":
            t = node[1]
            if t.bits < self.bits:
                t = Convert(m.next_atom(), t.bits, self.bits, False, t, **t.tags)
            if self.shift:
                t = BinaryOp(m.next_atom(), "Shl", [t, Const(m.next_atom(), self.shift, 8)], False, bits=self.bits)
            return t
        if kind == "C":
            outside = full & ~hole if choice.pop() else 0
            return Const(m.next_atom(), (node[1] << self.shift) | outside, self.bits)
        if kind == "N":
            child = self.build(node[1], choice)
            if choice.pop():
                return UnaryOp(m.next_atom(), "BitwiseNeg", child, bits=self.bits)
            return BinaryOp(m.next_atom(), "Xor", [child, Const(m.next_atom(), hole, self.bits)], False, bits=self.bits)
        a = self.build(node[1], choice)
        b = self.build(node[2], choice)
        return BinaryOp(m.next_atom(), kind, [a, b], False, bits=self.bits)


class VMInsertSimplifier(PeepholeOptimizationExprBase):
    """
    Scalar ``Insert(base, off, v)`` that merges a partial register write back into the full register:

    - ``v`` is the part of ``base`` it overwrites                       ==> ``base``
    - ``v`` is a bitwise function of that part and other values, e.g.
      ``Insert(b, 0, Conv(64->8, b) ^ y)`` ==> ``b ^ zext(y)``,
      ``Insert(b, 0, ~Conv(64->8, b))``     ==> ``b ^ 0xff``           ==> the same function over the full width
    - ``Insert(Insert(b, off, v1), off', v2)`` with v1 inside v2's hole ==> ``Insert(b, off', v2)``
    - every bit of ``base`` outside the hole is known (e.g. a zero-extended or constant base)
                                                                        ==> ``K | (zext(v) << off*8)``
    - ``Conv(B->n, Insert(b, off, v))`` with the hole inside the low n bits ==> ``Insert(Conv(B->n, b), off, v)``
    - ``Concat(c0, c1)`` of two constants                               ==> one constant
    """

    __slots__ = ()

    NAME = "Fold self-referential partial-register Inserts"
    expr_classes = (Insert, Convert, BinaryOp)

    def optimize(self, expr: Expression, *, block_defs=None, **kwargs):
        if isinstance(expr, Insert):
            return self._optimize_insert(expr, block_defs)
        if isinstance(expr, Convert):
            return self._optimize_convert(expr)
        if isinstance(expr, BinaryOp) and expr.op == "Concat":
            return self._optimize_concat(expr)
        return None

    def part(self, expr: Expression, shift: int, width: int, depth: int = 0) -> Expression | None:
        """A simplified expression for bits [shift, shift + width) of ``expr``, or None."""
        if shift == 0 and width == expr.bits:
            return expr
        if depth > _MAX_DEPTH or shift + width > expr.bits:
            return None
        c = _const_int(expr)
        if c is not None:
            return Const(None, (c >> shift) & _mask(width), width)
        if _is_int_convert(expr):
            inner = expr.operand
            if shift + width <= min(expr.from_bits, expr.to_bits):
                return self.part(inner, shift, width, depth + 1)
            if expr.to_bits > expr.from_bits and not expr.is_signed:
                if shift >= expr.from_bits:
                    return Const(None, 0, width)
                if shift == 0:
                    return Convert(None, expr.from_bits, width, False, inner)
        elif isinstance(expr, Extract):
            e_shift = _extract_shift(expr)
            if e_shift is not None:
                return self.part(expr.base, e_shift + shift, width, depth + 1)
        elif isinstance(expr, Insert):
            i_shift = _insert_shift(expr)
            if i_shift is not None:
                v_bits = expr.value.bits
                if i_shift <= shift and shift + width <= i_shift + v_bits:
                    return self.part(expr.value, shift - i_shift, width, depth + 1)
                if shift + width <= i_shift or i_shift + v_bits <= shift:
                    return self.part(expr.base, shift, width, depth + 1)
        elif isinstance(expr, BinaryOp) and not expr.floating_point:
            op0, op1 = expr.operands
            amount = _const_int(op1)
            if expr.op in {"And", "Or", "Xor"} and op0.bits == op1.bits == expr.bits:
                p0 = self.part(op0, shift, width, depth + 1)
                p1 = self.part(op1, shift, width, depth + 1)
                if p0 is None or p1 is None:
                    return None
                c0, c1 = _const_int(p0), _const_int(p1)
                if c1 is not None and c0 is None:
                    p0, p1, c0, c1 = p1, p0, c1, c0
                if c0 is not None and c1 is not None:
                    value = {"And": c0 & c1, "Or": c0 | c1, "Xor": c0 ^ c1}[expr.op]
                    return Const(None, value, width)
                if c0 is not None:
                    if c0 == 0:
                        return Const(None, 0, width) if expr.op == "And" else p1
                    if c0 == _mask(width) and expr.op == "And":
                        return p1
                    if c0 == _mask(width) and expr.op == "Or":
                        return Const(None, c0, width)
                return BinaryOp(None, expr.op, [p0, p1], False, bits=width)
            if expr.op == "Shl" and amount is not None and op0.bits == expr.bits:
                if shift + width <= amount:
                    return Const(None, 0, width)
                if shift >= amount:
                    return self.part(op0, shift - amount, width, depth + 1)
            elif expr.op == "Shr" and amount is not None and op0.bits == expr.bits:
                if shift + amount + width <= expr.bits:
                    return self.part(op0, shift + amount, width, depth + 1)
            elif expr.op == "Concat":
                low = op1.bits
                if shift + width <= low:
                    return self.part(op1, shift, width, depth + 1)
                if shift >= low:
                    return self.part(op0, shift - low, width, depth + 1)
        if shift:
            expr = BinaryOp(None, "Shr", [expr, Const(None, shift, 8)], False, bits=expr.bits)
        return Convert(None, expr.bits, width, False, expr)

    def is_part(self, candidate: Expression, low: Expression) -> bool:
        """Whether ``candidate`` is, structurally, the same bits as ``low`` (a result of :meth:`part`)."""
        canon = candidate
        if _is_int_convert(candidate) and candidate.to_bits < candidate.from_bits:
            canon = self.part(candidate.operand, 0, candidate.to_bits)
        elif isinstance(candidate, Extract):
            e_shift = _extract_shift(candidate)
            canon = None if e_shift is None else self.part(candidate.base, e_shift, candidate.bits)
        return canon is not None and canon.likes(low)

    def _optimize_insert(self, expr: Insert, block_defs=None) -> Expression | None:
        if expr.bits > _MAX_SCALAR_BITS or _visibly_fp(expr.value) or _visibly_fp(expr.base):
            return None
        shift = _insert_shift(expr)
        if shift is None:
            return None
        base, value = expr.base, expr.value
        width = value.bits
        hole = _mask(width) << shift
        full = _mask(expr.bits)

        # Insert(Concat(a, b), off, v) where the hole is exactly a or b: the Concat with that half replaced
        if isinstance(base, BinaryOp) and base.op == "Concat" and not _visibly_fp(value):
            hi, lo = base.operands
            if shift == 0 and width == lo.bits:
                return BinaryOp(expr.idx, "Concat", [hi, value], False, bits=expr.bits, **expr.tags)
            if shift == lo.bits and width == hi.bits:
                return BinaryOp(expr.idx, "Concat", [value, lo], False, bits=expr.bits, **expr.tags)

        # Insert(Insert(b, o1, v1), o2, v2) with v1's hole inside v2's
        if isinstance(base, Insert):
            inner_shift = _insert_shift(base)
            if inner_shift is not None and shift <= inner_shift and inner_shift + base.value.bits <= shift + width:
                return Insert(expr.idx, base.base, expr.offset, value, expr.endness, **expr.tags)

        low = self.part(base, shift, width)
        if low is not None:
            if self.is_part(value, low):
                return base
            lifter = _Lifter(self, base, shift, width, low)
            skeleton = lifter.scan(value)
            if skeleton is not None and lifter.uses_low and lifter.free <= _MAX_FREE:
                choice = lifter.solve(skeleton)
                if choice is not None:
                    # build() pops from the end in the order _eval() does
                    out = lifter.build(skeleton, list(choice))
                    return self._with_idx(out, expr)

        # Insert(x ^ K, off, v) == Insert(x, off, v) ^ (K outside the hole), likewise | and &
        if isinstance(base, BinaryOp) and base.op in {"Xor", "Or", "And"} and base.bits == expr.bits:
            for x, k in (base.operands, base.operands[::-1]):
                kv = _const_int(k)
                if kv is None or x.bits != expr.bits:
                    continue
                inner = Insert(self.manager.next_atom(), x, expr.offset, value, expr.endness, **expr.tags)
                simplified = self._optimize_insert(inner, block_defs)
                if simplified is None:
                    break
                kv = (kv | hole) & full if base.op == "And" else kv & full & ~hole
                if kv == (full if base.op == "And" else 0):
                    return self._with_idx(simplified, expr)
                k = Const(self.manager.next_atom(), kv, expr.bits)
                return BinaryOp(expr.idx, base.op, [simplified, k], False, bits=expr.bits, **expr.tags)

        zeros, ones = known_bits(base, block_defs_resolver(block_defs))
        if (zeros | ones) & full & ~hole == full & ~hole:
            m = self.manager
            part = value
            if part.bits < expr.bits:
                part = Convert(m.next_atom(), part.bits, expr.bits, False, part, **expr.tags)
            if shift:
                part = BinaryOp(m.next_atom(), "Shl", [part, Const(m.next_atom(), shift, 8)], False, bits=expr.bits)
            k = ones & full & ~hole
            if k == 0:
                return self._with_idx(part, expr)
            k_expr = Const(m.next_atom(), k, expr.bits)
            return BinaryOp(expr.idx, "Or", [part, k_expr], False, bits=expr.bits, **expr.tags)
        return None

    @staticmethod
    def _with_idx(out: Expression, expr: Expression) -> Expression:
        if isinstance(out, BinaryOp):
            return BinaryOp(expr.idx, out.op, list(out.operands), out.signed, bits=out.bits, **expr.tags)
        if isinstance(out, UnaryOp):
            return UnaryOp(expr.idx, out.op, out.operand, bits=out.bits, **expr.tags)
        if isinstance(out, Convert):
            return Convert(expr.idx, out.from_bits, out.to_bits, out.is_signed, out.operand, **expr.tags)
        return out

    def _optimize_convert(self, expr: Convert) -> Expression | None:
        ins = expr.operand
        if not (isinstance(ins, Insert) and _is_int_convert(expr) and expr.to_bits < expr.from_bits):
            return None
        if ins.bits > _MAX_SCALAR_BITS or ins.endness != archinfo.Endness.LE:
            return None
        shift = _insert_shift(ins)
        if shift is None or not (shift + ins.value.bits <= expr.to_bits and ins.value.bits < expr.to_bits):
            return None
        m = self.manager
        narrowed = Convert(m.next_atom(), expr.from_bits, expr.to_bits, False, ins.base, **ins.base.tags)
        return Insert(expr.idx, narrowed, ins.offset, ins.value, ins.endness, **expr.tags)

    def _optimize_concat(self, expr: BinaryOp) -> Expression | None:
        hi_e, lo_e = expr.operands
        # Concat(bits [n, n+m) of x, bits [0, n) of x) is the low n+m bits of x
        src = None
        if isinstance(lo_e, Extract) and _extract_shift(lo_e) == 0:
            src = lo_e.base
        elif _is_int_convert(lo_e) and lo_e.to_bits < lo_e.from_bits:
            src = lo_e.operand
        if src is not None and expr.bits <= src.bits <= _MAX_SCALAR_BITS and not _visibly_fp(src):
            hi_part = self.part(src, lo_e.bits, hi_e.bits)
            if hi_part is not None and self.is_part(hi_e, hi_part):
                if src.bits == expr.bits:
                    return src
                return Convert(expr.idx, src.bits, expr.bits, False, src, **expr.tags)
        hi, lo = _const_int(expr.operands[0]), _const_int(expr.operands[1])
        if hi is None or lo is None or expr.bits > _MAX_SCALAR_BITS:
            # an aggregate stays a Concat: RemoveConstInsert would otherwise widen values to its size
            return None
        lo_bits = expr.operands[1].bits
        value = ((hi & _mask(expr.operands[0].bits)) << lo_bits) | (lo & _mask(lo_bits))
        return Const(expr.idx, value, expr.bits, **expr.tags)
