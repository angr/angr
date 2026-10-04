"""
Evaluation of integer expressions derived from an x87 ``CmpF`` result or an ``fxam`` classification.

``CmpF`` yields one of four codes (GT 0x00, LT 0x01, EQ 0x40, unordered 0x45). ``fnstsw ax`` places them in AH
together with the (unknown) top-of-stack pointer; ``test ah, imm`` / ``sahf`` / ``and ah, 0x45; cmp ah, 0x40`` then
test individual bits. Instead of matching every such shape structurally, we evaluate the expression in a known-bits
domain once per outcome; the ``ftop`` contribution and the preserved OF bit of ``sahf`` drop out as unknown bits that
the final mask discards. The resulting outcome -> value table is then turned into an IEEE comparison.

``__fxam(x)`` is handled the same way over its outcomes: the C3/C2/C0 class bits (Intel SDM, FXAM) times the C1 sign.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence

import archinfo

from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Extract,
    Insert,
    Reinterpret,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.ailment.manager import Manager

CMPF_GT = 0x00
CMPF_LT = 0x01
CMPF_EQ = 0x40
CMPF_UN = 0x45
CMPF_OUTCOMES = (CMPF_GT, CMPF_LT, CMPF_EQ, CMPF_UN)

# fxam classes in status-word bit positions (C3 0x4000, C2 0x400, C0 0x100); C1 (0x200) is the sign. Empty and
# unsupported encodings are left out: fxam is applied to a valid double.
FXAM_NAN = 0x100
FXAM_NORMAL = 0x400
FXAM_INF = 0x500
FXAM_ZERO = 0x4000
FXAM_DENORMAL = 0x4400
FXAM_SIGN = 0x200
FXAM_CLASSES = frozenset({FXAM_NAN, FXAM_NORMAL, FXAM_INF, FXAM_ZERO, FXAM_DENORMAL})
FXAM_OUTCOMES = tuple(c | s for c in sorted(FXAM_CLASSES) for s in (0, FXAM_SIGN))

SOURCE_CMPF = "CmpF"
SOURCE_FXAM = "__fxam"
_FXAM_CCALLS = frozenset({"x86g_calculate_FXAM", "amd64g_calculate_FXAM"})

# known-bits value: (mask of known bits, value of the known bits)
_KnownBits = tuple[int, int]
_UNKNOWN: _KnownBits = (0, 0)

_ORDERED_PREDICATES: dict[frozenset[int], str] = {
    frozenset({CMPF_LT}): "CmpLT",
    frozenset({CMPF_GT}): "CmpGT",
    frozenset({CMPF_EQ}): "CmpEQ",
    frozenset({CMPF_LT, CMPF_EQ}): "CmpLE",
    frozenset({CMPF_GT, CMPF_EQ}): "CmpGE",
    frozenset({CMPF_LT, CMPF_GT}): "CmpNE",
}


class FswTable:
    """
    Values of one or more integer expressions for each outcome of the single CmpF or __fxam they are built from.

    ``values[outcome]`` holds one integer per evaluated expression.
    """

    __slots__ = ("operands", "source", "values")

    def __init__(self, source: str, operands: tuple[Expression, ...], values: dict[int, tuple[int, ...]]):
        self.source = source
        self.operands = operands
        self.values = values

    def true_set(self, pred: Callable[[tuple[int, ...]], bool]) -> frozenset[int]:
        return frozenset(o for o, vals in self.values.items() if pred(vals))


class _KnownBitsEvaluator:
    __slots__ = ("outcome", "source", "source_operands", "vvar_defs")

    def __init__(self, vvar_defs: dict[int, Expression] | None):
        self.source: str | None = None
        self.source_operands: tuple[Expression, ...] = ()
        self.outcome = CMPF_GT
        self.vvar_defs = vvar_defs

    def _source_value(self, source: str, operands: tuple[Expression, ...], mask: int) -> _KnownBits:
        if self.source is None:
            self.source = source
            self.source_operands = operands
        elif self.source != source or not all(a.likes(b) for a, b in zip(self.source_operands, operands, strict=True)):
            return _UNKNOWN
        return mask, self.outcome & mask

    @staticmethod
    def _mask(bits: int) -> int:
        return (1 << bits) - 1

    def eval(self, expr: Expression, depth: int = 0) -> _KnownBits:  # pylint:disable=too-many-return-statements
        if depth > 48:
            return _UNKNOWN
        bits = expr.bits
        mask = self._mask(bits)

        if isinstance(expr, Const):
            if not isinstance(expr.value, int):
                return _UNKNOWN
            return mask, expr.value & mask

        if isinstance(expr, VirtualVariable):
            if self.vvar_defs is not None and expr.varid in self.vvar_defs:
                return self.eval(self.vvar_defs[expr.varid], depth + 1)
            return _UNKNOWN

        if isinstance(expr, Convert):
            return self._eval_convert(expr, depth)

        if isinstance(expr, Extract):
            if not (isinstance(expr.offset, Const) and isinstance(expr.offset.value, int)):
                return _UNKNOWN
            k_base, v_base = self.eval(expr.base, depth + 1)
            shift = self._byte_offset_to_shift(expr.offset.value, bits, expr.base.bits, expr.endness)
            if shift is None:
                return _UNKNOWN
            return (k_base >> shift) & mask, (v_base >> shift) & mask

        if isinstance(expr, Insert):
            if not (isinstance(expr.offset, Const) and isinstance(expr.offset.value, int)):
                return _UNKNOWN
            k_base, v_base = self.eval(expr.base, depth + 1)
            k_val, v_val = self.eval(expr.value, depth + 1)
            shift = self._byte_offset_to_shift(expr.offset.value, expr.value.bits, bits, expr.endness)
            if shift is None:
                return _UNKNOWN
            hole = self._mask(expr.value.bits) << shift
            return (k_base & ~hole | k_val << shift) & mask, (v_base & ~hole | v_val << shift) & mask

        if isinstance(expr, UnaryOp):
            if expr.op == "Not":
                k, v = self.eval(expr.operand, depth + 1)
                return k, ~v & mask
            return _UNKNOWN

        if isinstance(expr, BinaryOp):
            return self._eval_binop(expr, bits, mask, depth)

        if isinstance(expr, Call) and expr.target == SOURCE_FXAM and expr.args is not None and len(expr.args) == 1:
            return self._source_value(SOURCE_FXAM, (expr.args[0],), mask)

        if isinstance(expr, VEXCCallExpression) and len(expr.operands) == 2:
            # calculate_FXAM(tag, Reinterpret(F64->I64, x)) before the ccall rewriter turns it into __fxam(x)
            callee = expr.tags.get("vex_callee", expr.callee) if expr.callee == "_ccall" else expr.callee
            value = expr.operands[1]
            if (
                callee in _FXAM_CCALLS
                and isinstance(value, Reinterpret)
                and value.from_type == "F"
                and value.to_type == "I"
            ):
                return self._source_value(SOURCE_FXAM, (value.operand,), mask)

        return _UNKNOWN

    @staticmethod
    def _byte_offset_to_shift(offset: int, part_bits: int, whole_bits: int, endness: str) -> int | None:
        shift = offset * 8 if endness == archinfo.Endness.LE else whole_bits - offset * 8 - part_bits
        if shift < 0 or shift + part_bits > whole_bits:
            return None
        return shift

    def _eval_convert(self, expr: Convert, depth: int) -> _KnownBits:
        if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
            return _UNKNOWN
        k, v = self.eval(expr.operand, depth + 1)
        from_mask = self._mask(expr.from_bits)
        to_mask = self._mask(expr.to_bits)
        if expr.to_bits <= expr.from_bits:
            return k & to_mask, v & to_mask
        ext = to_mask & ~from_mask
        if not expr.is_signed:
            return k | ext, v
        top = 1 << (expr.from_bits - 1)
        if not k & top:
            return k, v
        return k | ext, (v | ext) if v & top else v

    def _eval_binop(self, expr: BinaryOp, bits: int, mask: int, depth: int) -> _KnownBits:  # pylint:disable=too-many-return-statements
        if expr.op == "CmpF":
            return self._source_value(SOURCE_CMPF, (expr.operands[0], expr.operands[1]), mask)

        if expr.floating_point or expr.vector_count:
            return _UNKNOWN

        lhs, rhs = expr.operands
        k0, v0 = self.eval(lhs, depth + 1)

        if expr.op == "And":
            k1, v1 = self.eval(rhs, depth + 1)
            return (k0 & k1) | (k0 & ~v0) | (k1 & ~v1), v0 & v1
        if expr.op == "Or":
            k1, v1 = self.eval(rhs, depth + 1)
            return (k0 & k1) | (k0 & v0) | (k1 & v1), v0 | v1
        if expr.op == "Xor":
            k1, v1 = self.eval(rhs, depth + 1)
            return k0 & k1, v0 ^ v1

        if expr.op in {"Shl", "Shr", "Sar", "Mul"}:
            if not (isinstance(rhs, Const) and isinstance(rhs.value, int)):
                return _UNKNOWN
            c = rhs.value
            if expr.op == "Mul":
                if c == 0:
                    return mask, 0
                if c & (c - 1):
                    return (mask, (v0 * c) & mask) if k0 == mask else _UNKNOWN
                c = c.bit_length() - 1
            if c >= bits:
                return _UNKNOWN
            if expr.op in {"Shl", "Mul"}:
                return ((k0 << c) | self._mask(c)) & mask, (v0 << c) & mask
            if expr.op == "Shr":
                return (k0 >> c) | (mask & ~(mask >> c)), v0 >> c
            # Sar
            top = 1 << (bits - 1)
            if not k0 & top:
                return k0 >> c, v0 >> c
            fill = mask & ~(mask >> c)
            return (k0 >> c) | fill, (v0 >> c) | (fill if v0 & top else 0)

        if expr.op in {"Add", "Sub"}:
            k1, v1 = self.eval(rhs, depth + 1)
            if k0 != mask or k1 != mask:
                return _UNKNOWN
            return mask, (v0 + v1 if expr.op == "Add" else v0 - v1) & mask

        return _UNKNOWN


def evaluate_over_fsw(exprs: Sequence[Expression], vvar_defs: dict[int, Expression] | None = None) -> FswTable | None:
    """
    Evaluate integer expressions that depend on a single CmpF(a, b) or __fxam(x) for each of its outcomes.

    :return:    The table of values, or None if no source is found or any expression has unknown bits for some outcome.
    """
    evaluator = _KnownBitsEvaluator(vvar_defs)
    # the first pass finds the source
    for expr in exprs:
        evaluator.eval(expr)
    if evaluator.source is None:
        return None
    values: dict[int, tuple[int, ...]] = {}
    for outcome in CMPF_OUTCOMES if evaluator.source == SOURCE_CMPF else FXAM_OUTCOMES:
        evaluator.outcome = outcome
        vals = []
        for expr in exprs:
            known, value = evaluator.eval(expr)
            if known != (1 << expr.bits) - 1:
                return None
            vals.append(value)
        values[outcome] = tuple(vals)
    return FswTable(evaluator.source, evaluator.source_operands, values)


def fsw_predicate(
    table: FswTable, true_set: frozenset[int], idx: int | None, ail_manager: Manager, bits: int, tags: dict
) -> Expression | None:
    """The predicate that is true exactly for the outcomes in ``true_set``; None if it has no C spelling."""
    if table.source == SOURCE_CMPF:
        a, b = table.operands
        return fp_predicate_from_outcomes(true_set, (a, b), idx, ail_manager, bits, tags)
    return fxam_predicate(true_set, table.operands[0], idx, ail_manager, bits, tags)


# fxam class sets with a C spelling; the complement of each is spelled with a negation
_FXAM_PREDICATES: dict[frozenset[int], str] = {
    frozenset({FXAM_NAN}): "IsNaN",
    frozenset({FXAM_INF}): "IsInf",
    frozenset({FXAM_NORMAL, FXAM_ZERO, FXAM_DENORMAL}): "IsFinite",
    frozenset({FXAM_NORMAL}): "IsNormal",
    frozenset({FXAM_ZERO}): "CmpEQ",
}


def fxam_predicate(
    true_set: frozenset[int], x: Expression, idx: int | None, ail_manager: Manager, bits: int, tags: dict
) -> Expression | None:
    """
    Build the classification test of ``x`` that is true exactly for the fxam outcomes in ``true_set``: isnan, isinf,
    isfinite, isnormal, x == 0, signbit, or the negation of one of them.
    """
    positive = frozenset(o for o in true_set if not o & FXAM_SIGN)
    negative = frozenset(o & ~FXAM_SIGN for o in true_set if o & FXAM_SIGN)
    if positive != negative:
        if not positive and negative == FXAM_CLASSES:
            return UnaryOp(idx, "SignBit", x, bits=bits, **tags)
        if not negative and positive == FXAM_CLASSES:
            inner = UnaryOp(ail_manager.next_atom(), "SignBit", x, bits=bits, **tags)
            return UnaryOp(idx, "Not", inner, bits=bits, **tags)
        return None

    if not positive:
        return Const(idx, 0, bits, **tags)
    if positive == FXAM_CLASSES:
        return Const(idx, 1, bits, **tags)
    negate = False
    op = _FXAM_PREDICATES.get(positive)
    if op is None:
        negate = True
        op = _FXAM_PREDICATES.get(FXAM_CLASSES - positive)
        if op is None:
            return None
    if op == "CmpEQ":
        zero = Const(ail_manager.next_atom(), 0.0, x.bits, **tags)
        # x != 0.0 is exactly the complement (NaN != 0.0 holds)
        return BinaryOp(idx, "CmpNE" if negate else "CmpEQ", [x, zero], False, floating_point=True, bits=bits, **tags)
    if not negate:
        return UnaryOp(idx, op, x, bits=bits, **tags)
    pred = UnaryOp(ail_manager.next_atom(), op, x, bits=bits, **tags)
    return UnaryOp(idx, "Not", pred, bits=bits, **tags)


def fp_predicate_from_outcomes(
    true_set: frozenset[int],
    operands: tuple[Expression, Expression],
    idx: int | None,
    ail_manager: Manager,
    bits: int,
    tags: dict,
) -> Expression:
    """
    Build the comparison that is true exactly for the CmpF outcomes in ``true_set``.

    Unordered results are folded into the ordered comparison the same way compilers' ordered C comparisons are: the
    ordered subset decides the operator, and the predicate is lossy for NaN unless only the unordered case remains.
    """
    a, b = operands
    if a.likes(b):
        # comparing a value against itself: only EQ and unordered can happen
        true_set -= {CMPF_LT, CMPF_GT}
        if CMPF_EQ in true_set:
            true_set |= {CMPF_LT, CMPF_GT}
    ordered = true_set - {CMPF_UN}

    if not ordered or len(ordered) == 3:
        if not true_set:
            return Const(idx, 0, bits, **tags)
        if len(true_set) == 4:
            return Const(idx, 1, bits, **tags)
        # {UN} -> isnan(a) / isunordered(a, b); {LT, EQ, GT} -> its negation
        unordered = _unordered(a, b, idx if not ordered else ail_manager.next_atom(), bits, tags)
        if unordered is None:
            return Const(idx, 0 if not ordered else 1, bits, **tags)
        if not ordered:
            return unordered
        return UnaryOp(idx, "Not", unordered, bits=bits, **tags)

    return BinaryOp(idx, _ORDERED_PREDICATES[ordered], [a, b], False, floating_point=True, bits=bits, **tags)


def _unordered(a: Expression, b: Expression, idx: int | None, bits: int, tags: dict) -> Expression | None:
    """isnan(a), isunordered(a, b), or None when neither operand can be NaN."""
    terms = [a] if a.likes(b) else [a, b]
    terms = [t for t in terms if not (isinstance(t, Const) and not const_is_nan(t))]
    if not terms:
        return None
    if len(terms) == 1:
        return UnaryOp(idx, "IsNaN", terms[0], bits=bits, **tags)
    return BinaryOp(idx, "CmpUN", terms, False, floating_point=True, bits=bits, **tags)


def const_is_nan(const: Const) -> bool:
    value = const.value
    if isinstance(value, float):
        return math.isnan(value)
    if not isinstance(value, int):
        return False
    # an integer constant compared by CmpF is a float bit pattern
    if const.bits == 64:
        return (value >> 52) & 0x7FF == 0x7FF and value & ((1 << 52) - 1) != 0
    if const.bits == 32:
        return (value >> 23) & 0xFF == 0xFF and value & ((1 << 23) - 1) != 0
    return False
