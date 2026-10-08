"""
Evaluation of integer expressions derived from an x87 ``CmpF`` result or an ``fxam`` classification.

``CmpF`` yields one of four codes (GT 0x00, LT 0x01, EQ 0x40, unordered 0x45). ``fnstsw ax`` places them in AH
together with the (unknown) top-of-stack pointer; ``test ah, imm`` / ``sahf`` / ``and ah, 0x45; cmp ah, 0x40`` then
test individual bits. Instead of matching every such shape structurally, we evaluate the expression in a known-bits
domain once per outcome; the ``ftop`` contribution and the preserved OF bit of ``sahf`` drop out as unknown bits that
the final mask discards. The resulting outcome -> value table is then turned into an IEEE comparison.

``__fxam(x)`` is handled the same way over its outcomes: the C3/C2/C0 class bits (Intel SDM, FXAM) times the C1 sign.
``x87_fprem[1]_c3210(a, b)`` has every C3/C2/C1/C0 combination as an outcome (C2: the remainder is partial). A boolean
placed at the C2 position (``cond * 0x400``, how fsin/fcos/fptan report an out-of-range operand) has two outcomes.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

import archinfo

from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    DirtyExpression,
    Expression,
    Extract,
    Insert,
    Load,
    Register,
    Reinterpret,
    StackBaseOffset,
    Tmp,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Label, NoOp, Statement, Store

from .block_walkers import HasCallExprWalker, HasCallNotification

if TYPE_CHECKING:
    from angr.rustylib.ailment import TagsView

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

# fprem/fprem1 status bits: C3 0x4000, C2 0x400 (partial remainder), C1 0x200, C0 0x100
FSW_C2 = 0x400
FPREM_OUTCOMES = tuple(
    c3 | c2 | c1 | c0 for c3 in (0, 0x4000) for c2 in (0, FSW_C2) for c1 in (0, 0x200) for c0 in (0, 0x100)
)
BOOL_OUTCOMES = (0, 1)

SOURCE_CMPF = "CmpF"
SOURCE_FXAM = "__fxam"
SOURCE_FPREM = "x87_fprem_c3210"
SOURCE_FPREM1 = "x87_fprem1_c3210"
SOURCE_C2_BOOL = "c2_bool"
_FPREM_SOURCES = frozenset({SOURCE_FPREM, SOURCE_FPREM1})
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


LoadResolver = Callable[[Load], Expression | None]


class _KnownBitsEvaluator:
    __slots__ = ("budget", "load_resolver", "memo", "outcome", "source", "source_operands", "tmp_defs", "vvar_defs")

    # definitions form a DAG; without memoization a shared sub-expression is re-walked once per path
    MAX_NODES = 256

    def __init__(
        self,
        vvar_defs: dict[int, Expression] | None,
        load_resolver: LoadResolver | None = None,
        tmp_defs: dict[int, Expression] | None = None,
    ):
        self.source: str | None = None
        self.source_operands: tuple[Expression, ...] = ()
        self.outcome = CMPF_GT
        self.vvar_defs = vvar_defs
        self.load_resolver = load_resolver
        self.tmp_defs = tmp_defs
        self.memo: dict[tuple[str, int], _KnownBits] = {}
        self.budget = self.MAX_NODES

    def set_outcome(self, outcome: int) -> None:
        self.outcome = outcome
        self.memo.clear()
        self.budget = self.MAX_NODES

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
        if depth > 48 or self.budget <= 0:
            return _UNKNOWN
        self.budget -= 1
        bits = expr.bits
        mask = self._mask(bits)

        if isinstance(expr, Const):
            if not isinstance(expr.value, int):
                return _UNKNOWN
            return mask, expr.value & mask

        if isinstance(expr, VirtualVariable):
            if self.vvar_defs is not None and expr.varid in self.vvar_defs:
                return self._eval_def(("v", expr.varid), self.vvar_defs[expr.varid], depth)
            return _UNKNOWN

        if isinstance(expr, Tmp):
            if self.tmp_defs is not None and expr.tmp_idx in self.tmp_defs:
                return self._eval_def(("t", expr.tmp_idx), self.tmp_defs[expr.tmp_idx], depth)
            return _UNKNOWN

        if isinstance(expr, Convert):
            return self._eval_convert(expr, depth)

        if isinstance(expr, Load):
            if self.load_resolver is not None and (stored := self.load_resolver(expr)) is not None:
                return self.eval(stored, depth + 1)
            return _UNKNOWN

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

        if isinstance(expr, DirtyExpression) and expr.callee in _FPREM_SOURCES and len(expr.operands) == 2:
            return self._source_value(expr.callee, (expr.operands[0], expr.operands[1]), mask)

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

    def _eval_def(self, key: tuple[str, int], definition: Expression, depth: int) -> _KnownBits:
        if key not in self.memo:
            self.memo[key] = _UNKNOWN  # cycle guard
            self.memo[key] = self.eval(definition, depth + 1)
        return self.memo[key]

    @staticmethod
    def _c2_bool(expr: BinaryOp) -> Expression | None:
        """The 1-bit comparison in ``Conv(1->N, cond) * 0x400`` (or ``<< 10``), else None."""
        lhs, rhs = expr.operands
        if not (isinstance(rhs, Const) and rhs.value == (FSW_C2 if expr.op == "Mul" else 10)):
            return None
        if not (isinstance(lhs, Convert) and lhs.from_bits == 1 and lhs.from_type == Convert.TYPE_INT):
            return None
        cond = lhs.operand
        if isinstance(cond, BinaryOp) and cond.bits == 1 and cond.op.startswith("Cmp") and cond.op != "CmpF":
            return cond
        return None

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
        if expr.op in {"Mul", "Shl"} and (c2_bool := self._c2_bool(expr)) is not None:
            k_bool, v_bool = self.eval(c2_bool, depth + 1)
            if not k_bool & 1:
                k_bool, v_bool = self._source_value(SOURCE_C2_BOOL, (c2_bool,), 1)
            return (mask & ~FSW_C2) | (k_bool & 1) << 10, (v_bool & 1) << 10
        k0, v0 = self.eval(lhs, depth + 1)

        if expr.op in {"CmpEQ", "CmpNE"}:
            k1, v1 = self.eval(rhs, depth + 1)
            both = k0 & k1
            if (v0 ^ v1) & both:
                return 1, int(expr.op == "CmpNE")
            if both == self._mask(lhs.bits):
                return 1, int(expr.op == "CmpEQ")
            return _UNKNOWN

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

        if expr.op == "Concat":
            k1, v1 = self.eval(rhs, depth + 1)
            return (k0 << rhs.bits | k1) & mask, (v0 << rhs.bits | v1) & mask

        if expr.op in {"Add", "Sub"}:
            k1, v1 = self.eval(rhs, depth + 1)
            if k0 != mask or k1 != mask:
                return _UNKNOWN
            return mask, (v0 + v1 if expr.op == "Add" else v0 - v1) & mask

        return _UNKNOWN


def evaluate_over_fsw(
    exprs: Sequence[Expression],
    vvar_defs: dict[int, Expression] | None = None,
    load_resolver: LoadResolver | None = None,
    tmp_defs: dict[int, Expression] | None = None,
) -> FswTable | None:
    """
    Evaluate integer expressions that depend on a single CmpF(a, b), __fxam(x), x87_fprem[1]_c3210(a, b) or C2 boolean
    for each of its outcomes.

    :param load_resolver:   Maps a Load to the expression it reads (e.g., a status word stored earlier), or None.
    :return:    The table of values, or None if no source is found or any expression has unknown bits for some outcome.
    """
    evaluator = _KnownBitsEvaluator(vvar_defs, load_resolver, tmp_defs)
    # the first pass finds the source
    for expr in exprs:
        evaluator.eval(expr)
    if evaluator.source is None:
        return None
    values: dict[int, tuple[int, ...]] = {}
    for outcome in _SOURCE_OUTCOMES[evaluator.source]:
        evaluator.set_outcome(outcome)
        vals = []
        for expr in exprs:
            known, value = evaluator.eval(expr)
            if known != (1 << expr.bits) - 1:
                return None
            vals.append(value)
        values[outcome] = tuple(vals)
    return FswTable(evaluator.source, evaluator.source_operands, values)


_SOURCE_OUTCOMES: dict[str, tuple[int, ...]] = {
    SOURCE_CMPF: CMPF_OUTCOMES,
    SOURCE_FXAM: FXAM_OUTCOMES,
    SOURCE_FPREM: FPREM_OUTCOMES,
    SOURCE_FPREM1: FPREM_OUTCOMES,
    SOURCE_C2_BOOL: BOOL_OUTCOMES,
}


def fsw_predicate(
    table: FswTable,
    true_set: frozenset[int],
    idx: int | None,
    ail_manager: Manager,
    bits: int,
    tags: TagsView | dict[str, Any],
) -> Expression | None:
    """The predicate that is true exactly for the outcomes in ``true_set``; None if it has no C spelling."""
    if table.source == SOURCE_CMPF:
        a, b = table.operands
        return fp_predicate_from_outcomes(true_set, (a, b), idx, ail_manager, bits, tags)
    if table.source == SOURCE_FXAM:
        return fxam_predicate(true_set, table.operands[0], idx, ail_manager, bits, tags)
    if table.source == SOURCE_C2_BOOL:
        if len(true_set) != 1:
            return Const(idx, int(bool(true_set)), bits, **tags)
        cond = table.operands[0]
        if 0 in true_set:
            cond = UnaryOp(idx if cond.bits == bits else ail_manager.next_atom(), "Not", cond, bits=cond.bits, **tags)
        return cond if cond.bits == bits else Convert(idx, cond.bits, bits, False, cond, **tags)
    return None


# fxam class sets with a C spelling; the complement of each is spelled with a negation
_FXAM_PREDICATES: dict[frozenset[int], str] = {
    frozenset({FXAM_NAN}): "IsNaN",
    frozenset({FXAM_INF}): "IsInf",
    frozenset({FXAM_NORMAL, FXAM_ZERO, FXAM_DENORMAL}): "IsFinite",
    frozenset({FXAM_NORMAL}): "IsNormal",
    frozenset({FXAM_ZERO}): "CmpEQ",
}


def fxam_predicate(
    true_set: frozenset[int],
    x: Expression,
    idx: int | None,
    ail_manager: Manager,
    bits: int,
    tags: TagsView | dict[str, Any],
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
    tags: TagsView | dict[str, Any],
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


def lower_cmpf_value(expr: Expression, ail_manager: Manager) -> Expression | None:
    """
    Exact C for an integer expression of one CmpF(a, b) and constants:
    ``isunordered(a, b) ? v_un : a == b ? v_eq : a < b ? v_lt : v_gt``. A constant OR-ed on top (e.g., the ftop bits of
    a status word) is kept. A test whose value equals the fall-through value is dropped: later tests are false for the
    outcomes tested before them.

    :return:    The replacement, or None if expr is not such an expression.
    """
    if isinstance(expr, BinaryOp) and expr.op == "Or":
        lhs, rhs = expr.operands
        if isinstance(lhs, Const) or isinstance(rhs, Const):
            const, other = (lhs, rhs) if isinstance(lhs, Const) else (rhs, lhs)
            lowered = lower_cmpf_value(other, ail_manager)
            if lowered is None:
                return None
            return BinaryOp(expr.idx, "Or", [const, lowered], False, bits=expr.bits, **expr.tags)

    table = evaluate_over_fsw([expr])
    if table is None or table.source != SOURCE_CMPF:
        return None
    a, b = table.operands
    tags = expr.tags
    if any(isinstance(op, Const) and const_is_nan(op) for op in (a, b)):
        outcomes = [CMPF_UN]
    elif all(isinstance(op, Const) for op in (a, b)):
        outcomes = [CMPF_EQ, CMPF_LT, CMPF_GT]
    elif a.likes(b):
        outcomes = [CMPF_UN, CMPF_EQ]
    else:
        outcomes = [CMPF_UN, CMPF_EQ, CMPF_LT, CMPF_GT]

    default = table.values[outcomes[-1]][0]
    result: Expression = Const(ail_manager.next_atom(), default, expr.bits, **tags)
    for o in reversed(outcomes[:-1]):
        v = table.values[o][0]
        if v == default:
            continue
        if o == CMPF_UN:
            cond = _unordered(a, b, ail_manager.next_atom(), 1, tags)
            assert cond is not None
        else:
            op = "CmpEQ" if o == CMPF_EQ else "CmpLT"
            cond = BinaryOp(ail_manager.next_atom(), op, [a, b], False, floating_point=True, bits=1, **tags)
        if isinstance(result, Const) and result.value == 0 and v == 1:
            # c ? 1 : 0 -> c
            result = cond if expr.bits == 1 else Convert(ail_manager.next_atom(), 1, expr.bits, False, cond, **tags)
        else:
            iftrue = Const(ail_manager.next_atom(), v, expr.bits, **tags)
            result = ITE(ail_manager.next_atom(), cond, iftrue, result, **tags)
    return result


def _unordered(
    a: Expression, b: Expression, idx: int | None, bits: int, tags: TagsView | dict[str, Any]
) -> Expression | None:
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


_HAS_CALL_WALKER = HasCallExprWalker()


def _has_call(stmt: Statement) -> bool:
    try:
        _HAS_CALL_WALKER.walk_statement(stmt)
    except HasCallNotification:
        return True
    return False


def _split_addr(addr: Expression) -> tuple[Expression | None, int] | None:
    """(base, offset) of an address; base None stands for the stack pointer at function entry."""
    if isinstance(addr, StackBaseOffset):
        return (None, addr.offset) if isinstance(addr.offset, int) else None
    if (
        isinstance(addr, BinaryOp)
        and addr.op in {"Add", "Sub"}
        and isinstance(addr.operands[1], Const)
        and isinstance(addr.operands[1].value, int)
    ):
        c = addr.operands[1].value
        return addr.operands[0], c if addr.op == "Add" else -c
    return addr, 0


def store_forwarder(
    statements: Sequence[Statement], stmt_idx: int, has_call_memo: dict[int, bool] | None = None
) -> LoadResolver:
    """
    Resolve a Load in statement ``stmt_idx`` to the data of an earlier Store in the same block that fully covers it,
    e.g. ``fnstsw word [ebp-0xa0]; test byte [ebp-0x9f], 0x41``. The search stops at any statement that may write
    memory the Load could read.
    """

    if has_call_memo is None:
        has_call_memo = {}  # by statement index; the walk is costly on deep expressions

    def has_call(i: int) -> bool:
        if i not in has_call_memo:
            has_call_memo[i] = _has_call(statements[i])
        return has_call_memo[i]

    def resolve(load: Load) -> Expression | None:
        load_addr = _split_addr(load.addr)
        if load_addr is None:
            return None
        load_base, load_off = load_addr
        for i in range(stmt_idx - 1, -1, -1):
            stmt = statements[i]
            if isinstance(stmt, (Label, NoOp)):
                continue
            if isinstance(stmt, Assignment):
                # a register write (before SSA) may change the address base
                if isinstance(stmt.dst, Register) or has_call(i):
                    return None
                continue
            if not isinstance(stmt, Store) or stmt.guard is not None or has_call(i):
                return None
            store_addr = _split_addr(stmt.addr)
            if store_addr is None:
                return None
            store_base, store_off = store_addr
            if (store_base is None) != (load_base is None) or (
                store_base is not None and load_base is not None and not store_base.likes(load_base)
            ):
                return None
            delta = load_off - store_off
            if load_off + load.size <= store_off or store_off + stmt.size <= load_off:
                # disjoint from the loaded bytes
                continue
            if delta < 0 or delta + load.size > stmt.size or stmt.endness != load.endness:
                return None
            if delta == 0 and load.size == stmt.size:
                return stmt.data
            return Extract(None, load.size * 8, stmt.data, Const(None, delta, 64), stmt.endness)
        return None

    return resolve
