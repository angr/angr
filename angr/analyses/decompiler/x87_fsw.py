"""
Evaluation of integer expressions derived from an x87 ``CmpF`` result.

``CmpF`` yields one of four codes (GT 0x00, LT 0x01, EQ 0x40, unordered 0x45). ``fnstsw ax`` places them in AH
together with the (unknown) top-of-stack pointer; ``test ah, imm`` / ``sahf`` / ``and ah, 0x45; cmp ah, 0x40`` then
test individual bits. Instead of matching every such shape structurally, we evaluate the expression in a known-bits
domain once per outcome; the ``ftop`` contribution and the preserved OF bit of ``sahf`` drop out as unknown bits that
the final mask discards. The resulting outcome -> value table is then turned into an IEEE comparison.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence

import archinfo

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Extract, Insert, UnaryOp, VirtualVariable
from angr.ailment.manager import Manager

CMPF_GT = 0x00
CMPF_LT = 0x01
CMPF_EQ = 0x40
CMPF_UN = 0x45
CMPF_OUTCOMES = (CMPF_GT, CMPF_LT, CMPF_EQ, CMPF_UN)

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


class CmpFTable:
    """
    Values of one or more integer expressions for each outcome of the single CmpF they are built from.

    ``values[outcome]`` holds one integer per evaluated expression.
    """

    __slots__ = ("operands", "values")

    def __init__(self, operands: tuple[Expression, Expression], values: dict[int, tuple[int, ...]]):
        self.operands = operands
        self.values = values

    def true_set(self, pred: Callable[[tuple[int, ...]], bool]) -> frozenset[int]:
        return frozenset(o for o, vals in self.values.items() if pred(vals))


class _KnownBitsEvaluator:
    __slots__ = ("cmpf_operands", "outcome", "vvar_defs")

    def __init__(self, vvar_defs: dict[int, Expression] | None):
        self.cmpf_operands: tuple[Expression, Expression] | None = None
        self.outcome = CMPF_GT
        self.vvar_defs = vvar_defs

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
            ops = expr.operands
            if self.cmpf_operands is None:
                self.cmpf_operands = (ops[0], ops[1])
            elif not (self.cmpf_operands[0].likes(ops[0]) and self.cmpf_operands[1].likes(ops[1])):
                return _UNKNOWN
            return mask, self.outcome & mask

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


def evaluate_over_cmpf(exprs: Sequence[Expression], vvar_defs: dict[int, Expression] | None = None) -> CmpFTable | None:
    """
    Evaluate integer expressions that depend on a single CmpF(a, b) for each of its four outcomes.

    :return:    The table of values, or None if no CmpF is found or any expression has unknown bits for some outcome.
    """
    evaluator = _KnownBitsEvaluator(vvar_defs)
    values: dict[int, tuple[int, ...]] = {}
    for outcome in CMPF_OUTCOMES:
        evaluator.outcome = outcome
        vals = []
        for expr in exprs:
            known, value = evaluator.eval(expr)
            if known != (1 << expr.bits) - 1:
                return None
            vals.append(value)
        if evaluator.cmpf_operands is None:
            return None
        values[outcome] = tuple(vals)
    assert evaluator.cmpf_operands is not None
    return CmpFTable(evaluator.cmpf_operands, values)


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
