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
import struct
from collections.abc import Callable, Mapping, Sequence
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

# outcomes for which a float comparison of the CmpF operands holds; CmpNE holds when unordered, as in C
_FP_CMP_TRUTH: dict[str, frozenset[int]] = {
    "CmpEQ": frozenset({CMPF_EQ}),
    "CmpNE": frozenset({CMPF_LT, CMPF_GT, CMPF_UN}),
    "CmpLT": frozenset({CMPF_LT}),
    "CmpLE": frozenset({CMPF_LT, CMPF_EQ}),
    "CmpGT": frozenset({CMPF_GT}),
    "CmpGE": frozenset({CMPF_GT, CMPF_EQ}),
    "CmpUN": frozenset({CMPF_UN}),
}
_INT_ORDER_CMPS: dict[str, Callable[[int, int], bool]] = {
    "CmpLT": lambda a, b: a < b,
    "CmpLE": lambda a, b: a <= b,
    "CmpGT": lambda a, b: a > b,
    "CmpGE": lambda a, b: a >= b,
}
_FP_CMP_MIRROR = {"CmpLT": "CmpGT", "CmpLE": "CmpGE", "CmpGT": "CmpLT", "CmpGE": "CmpLE"}

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
    __slots__ = (
        "budget",
        "fp_compare_leaves",
        "load_resolver",
        "memo",
        "outcome",
        "source",
        "source_operands",
        "tmp_defs",
        "vvar_defs",
    )

    # definitions form a DAG; without memoization a shared sub-expression is re-walked once per path
    MAX_NODES = 256

    def __init__(
        self,
        vvar_defs: Mapping[int, Expression] | None,
        load_resolver: LoadResolver | None = None,
        tmp_defs: dict[int, Expression] | None = None,
        fp_compare_leaves: bool = False,
    ):
        self.source: str | None = None
        self.source_operands: tuple[Expression, ...] = ()
        self.outcome = CMPF_GT
        self.vvar_defs = vvar_defs
        self.load_resolver = load_resolver
        self.tmp_defs = tmp_defs
        # also evaluate float comparisons (and NaN tests) of the CmpF operands, which earlier rewrites leave behind
        self.fp_compare_leaves = fp_compare_leaves
        # (definition kind, index, care) -> value
        self.memo: dict[tuple[str, int, int], _KnownBits] = {}
        self.budget = self.MAX_NODES

    def set_outcome(self, outcome: int) -> None:
        self.outcome = outcome
        self.memo.clear()
        self.budget = self.MAX_NODES

    def _source_value(self, source: str, operands: tuple[Expression, ...], mask: int) -> _KnownBits:
        if self.source is None:
            self.source = source
            self.source_operands = operands
        elif self.source != source or not all(
            self._same_operand(a, b) for a, b in zip(self.source_operands, operands, strict=True)
        ):
            return _UNKNOWN
        return mask, self.outcome & mask

    def _same_operand(self, a: Expression, b: Expression) -> bool:
        if a.likes(b):
            return True
        return self.fp_compare_leaves and self.source == SOURCE_CMPF and fp_operands_match(a, b)

    def _resolve_copy(self, expr: Expression) -> Expression:
        """Follow tmp copies (t = vvar, t = t') so that comparison operands match the CmpF operands."""
        seen = 0
        while isinstance(expr, Tmp) and self.tmp_defs is not None and expr.tmp_idx in self.tmp_defs and seen < 8:
            def_ = self.tmp_defs[expr.tmp_idx]
            if not isinstance(_strip_fp_widening(def_), (Tmp, VirtualVariable, Const)):
                break
            expr = def_
            seen += 1
        return expr

    def _fp_compare_value(self, expr: BinaryOp, mask: int) -> _KnownBits:
        a, b = self._resolve_copy(expr.operands[0]), self._resolve_copy(expr.operands[1])
        op = expr.op
        if self.source is None:
            self.source = SOURCE_CMPF
            self.source_operands = (a, b)
        elif self.source != SOURCE_CMPF:
            return _UNKNOWN
        src_a, src_b = self.source_operands
        if not (fp_operands_match(a, src_a) and fp_operands_match(b, src_b)):
            if not (fp_operands_match(a, src_b) and fp_operands_match(b, src_a)):
                return _UNKNOWN
            op = _FP_CMP_MIRROR.get(op, op)
        return mask, int(self.outcome in _FP_CMP_TRUTH[op]) & mask

    def _isnan_value(self, expr: UnaryOp, mask: int) -> _KnownBits:
        if self.source != SOURCE_CMPF:
            return _UNKNOWN
        src_a, src_b = self.source_operands
        x = self._resolve_copy(expr.operand)
        # a NaN test of either operand is the unordered outcome of the comparison, even when the other operand may be
        # NaN too: the printed comparison is the source-level ordered predicate (IDA folds the test the same way)
        if any(fp_operands_match(x, operand) for operand in (src_a, src_b)):
            return mask, int(self.outcome == CMPF_UN) & mask
        return _UNKNOWN

    @staticmethod
    def _mask(bits: int) -> int:
        return (1 << bits) - 1

    def eval(self, expr: Expression, depth: int = 0, care: int = -1) -> _KnownBits:  # pylint:disable=too-many-return-statements
        """
        :param care:    The result bits the caller uses; the others may come back as anything, "known" or not. Letting
                        masked-out sub-expressions (e.g. the previous FPSCR value in ``(fpscr & 0x0fffffff) | ...``)
                        go unevaluated keeps them from claiming the source or the budget.
        """
        bits = expr.bits
        mask = self._mask(bits)
        care &= mask
        if care == 0:
            return mask, 0
        if depth > 48 or self.budget <= 0:
            return _UNKNOWN
        self.budget -= 1

        if isinstance(expr, Const):
            if not isinstance(expr.value, int):
                return _UNKNOWN
            return mask, expr.value & mask

        if isinstance(expr, VirtualVariable):
            if self.vvar_defs is not None and expr.varid in self.vvar_defs:
                return self._eval_def(("v", expr.varid, care), self.vvar_defs[expr.varid], depth, care)
            return _UNKNOWN

        if isinstance(expr, Tmp):
            if self.tmp_defs is not None and expr.tmp_idx in self.tmp_defs:
                return self._eval_def(("t", expr.tmp_idx, care), self.tmp_defs[expr.tmp_idx], depth, care)
            return _UNKNOWN

        if isinstance(expr, Convert):
            return self._eval_convert(expr, depth, care)

        if isinstance(expr, Load):
            if self.load_resolver is not None and (stored := self.load_resolver(expr)) is not None:
                return self.eval(stored, depth + 1, care)
            return _UNKNOWN

        if isinstance(expr, Extract):
            if not (isinstance(expr.offset, Const) and isinstance(expr.offset.value, int)):
                return _UNKNOWN
            shift = self._byte_offset_to_shift(expr.offset.value, bits, expr.base.bits, expr.endness)
            if shift is None:
                return _UNKNOWN
            k_base, v_base = self.eval(expr.base, depth + 1, care << shift)
            return (k_base >> shift) & mask, (v_base >> shift) & mask

        if isinstance(expr, Insert):
            if not (isinstance(expr.offset, Const) and isinstance(expr.offset.value, int)):
                return _UNKNOWN
            shift = self._byte_offset_to_shift(expr.offset.value, expr.value.bits, bits, expr.endness)
            if shift is None:
                return _UNKNOWN
            hole = self._mask(expr.value.bits) << shift
            k_base, v_base = self.eval(expr.base, depth + 1, care & ~hole)
            k_val, v_val = self.eval(expr.value, depth + 1, care >> shift)
            return (k_base & ~hole | k_val << shift) & mask, (v_base & ~hole | v_val << shift) & mask

        if isinstance(expr, ITE):
            k_cond, v_cond = self.eval(expr.cond, depth + 1)
            if k_cond == self._mask(expr.cond.bits):
                return self.eval(expr.iftrue if v_cond else expr.iffalse, depth + 1)
            # unknown condition: the bits both branches agree on
            k_t, v_t = self.eval(expr.iftrue, depth + 1)
            k_f, v_f = self.eval(expr.iffalse, depth + 1)
            k = k_t & k_f & ~(v_t ^ v_f)
            return k, v_t & k

        if isinstance(expr, UnaryOp):
            if expr.op == "Not":
                k, v = self.eval(expr.operand, depth + 1, care)
                return k, ~v & mask
            if expr.op == "IsNaN" and self.fp_compare_leaves:
                return self._isnan_value(expr, mask)
            return _UNKNOWN

        if isinstance(expr, BinaryOp):
            return self._eval_binop(expr, bits, mask, depth, care)

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

    def _eval_def(self, key: tuple[str, int, int], definition: Expression, depth: int, care: int) -> _KnownBits:
        if key not in self.memo:
            self.memo[key] = _UNKNOWN  # cycle guard
            self.memo[key] = self.eval(definition, depth + 1, care)
        return self.memo[key]

    def _eval_shift(  # pylint:disable=too-many-return-statements
        self, expr: BinaryOp, lhs: Expression, c: int, bits: int, mask: int, depth: int, care: int
    ) -> _KnownBits:
        """Shl/Shr/Sar/Mul by the constant ``c``."""
        if expr.op == "Mul":
            if c == 0:
                return mask, 0
            if c & (c - 1):
                # the low bits of a product only depend on the low bits of the operand
                k0, v0 = self.eval(lhs, depth + 1, self._mask(care.bit_length()))
                return (mask, (v0 * c) & mask) if k0 == mask else _UNKNOWN
            c = c.bit_length() - 1
        if c >= bits:
            return _UNKNOWN
        if expr.op in {"Shl", "Mul"}:
            k0, v0 = self.eval(lhs, depth + 1, care >> c)
            return ((k0 << c) | self._mask(c)) & mask, (v0 << c) & mask
        if expr.op == "Shr":
            k0, v0 = self.eval(lhs, depth + 1, (care << c) & mask)
            return (k0 >> c) | (mask & ~(mask >> c)), v0 >> c
        # Sar
        top = 1 << (bits - 1)
        fill = mask & ~(mask >> c)
        k0, v0 = self.eval(lhs, depth + 1, ((care << c) & mask) | (top if care & fill else 0))
        if not k0 & top:
            return k0 >> c, v0 >> c
        return (k0 >> c) | fill, (v0 >> c) | (fill if v0 & top else 0)

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

    def _eval_convert(self, expr: Convert, depth: int, care: int) -> _KnownBits:
        if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
            return _UNKNOWN
        from_mask = self._mask(expr.from_bits)
        to_mask = self._mask(expr.to_bits)
        top = 1 << (expr.from_bits - 1)
        # the sign-extended bits come from the operand's top bit
        operand_care = care & from_mask
        if expr.is_signed and care & ~from_mask:
            operand_care |= top
        k, v = self.eval(expr.operand, depth + 1, operand_care)
        if expr.to_bits <= expr.from_bits:
            return k & to_mask, v & to_mask
        ext = to_mask & ~from_mask
        if not expr.is_signed:
            return k | ext, v
        if not k & top:
            return k, v
        return k | ext, (v | ext) if v & top else v

    def _eval_binop(self, expr: BinaryOp, bits: int, mask: int, depth: int, care: int) -> _KnownBits:  # pylint:disable=too-many-return-statements
        if expr.op == "CmpF":
            return self._source_value(SOURCE_CMPF, (expr.operands[0], expr.operands[1]), mask)

        if self.fp_compare_leaves and expr.floating_point and not expr.vector_count and expr.op in _FP_CMP_TRUTH:
            return self._fp_compare_value(expr, mask)

        if expr.floating_point or expr.vector_count:
            return _UNKNOWN

        lhs, rhs = expr.operands
        if expr.op in {"Mul", "Shl"} and (c2_bool := self._c2_bool(expr)) is not None:
            k_bool, v_bool = self.eval(c2_bool, depth + 1)
            if not k_bool & 1:
                k_bool, v_bool = self._source_value(SOURCE_C2_BOOL, (c2_bool,), 1)
            return (mask & ~FSW_C2) | (k_bool & 1) << 10, (v_bool & 1) << 10

        if expr.op in {"And", "Or"}:
            # bits the right operand fixes (known 0 for And, known 1 for Or) do not depend on the left operand
            k1, v1 = self.eval(rhs, depth + 1, care)
            fixed = k1 & ~v1 if expr.op == "And" else k1 & v1
            k0, v0 = self.eval(lhs, depth + 1, care & ~fixed)
            if expr.op == "And":
                return (k0 & k1) | (k0 & ~v0) | (k1 & ~v1), v0 & v1
            return (k0 & k1) | (k0 & v0) | (k1 & v1), v0 | v1
        if expr.op == "Xor":
            k0, v0 = self.eval(lhs, depth + 1, care)
            k1, v1 = self.eval(rhs, depth + 1, care)
            return k0 & k1, v0 ^ v1
        if expr.op in {"Shl", "Shr", "Sar", "Mul"} and isinstance(rhs, Const) and isinstance(rhs.value, int):
            return self._eval_shift(expr, lhs, rhs.value, bits, mask, depth, care)

        k0, v0 = self.eval(lhs, depth + 1)

        if expr.op in {"CmpEQ", "CmpNE"}:
            k1, v1 = self.eval(rhs, depth + 1)
            both = k0 & k1
            if (v0 ^ v1) & both:
                return 1, int(expr.op == "CmpNE")
            if both == self._mask(lhs.bits):
                return 1, int(expr.op == "CmpEQ")
            return _UNKNOWN

        if expr.op in {"LogicalAnd", "LogicalOr"} and self.fp_compare_leaves:
            k1, v1 = self.eval(rhs, depth + 1)
            if k0 != self._mask(lhs.bits) or k1 != self._mask(rhs.bits):
                return _UNKNOWN
            r = (v0 != 0 and v1 != 0) if expr.op == "LogicalAnd" else (v0 != 0 or v1 != 0)
            return mask, int(r)
        if expr.op in _INT_ORDER_CMPS and self.fp_compare_leaves:
            k1, v1 = self.eval(rhs, depth + 1)
            width = lhs.bits
            if k0 != self._mask(width) or k1 != self._mask(width):
                return _UNKNOWN
            if expr.signed:
                top = 1 << (width - 1)
                v0, v1 = (v0 ^ top) - top, (v1 ^ top) - top
            return mask, int(_INT_ORDER_CMPS[expr.op](v0, v1))

        if expr.op in {"Shl", "Shr", "Sar", "Mul"}:
            # shifts by a non-constant amount
            return _UNKNOWN

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
    vvar_defs: Mapping[int, Expression] | None = None,
    load_resolver: LoadResolver | None = None,
    tmp_defs: dict[int, Expression] | None = None,
    fp_compare_leaves: bool = False,
) -> FswTable | None:
    """
    Evaluate integer expressions that depend on a single CmpF(a, b), __fxam(x), x87_fprem[1]_c3210(a, b) or C2 boolean
    for each of its outcomes.

    :param load_resolver:   Maps a Load to the expression it reads (e.g., a status word stored earlier), or None.
    :param fp_compare_leaves:   Also treat float comparisons and NaN tests of the CmpF operands as functions of the
                                outcome.
    :return:    The table of values, or None if no source is found or any expression has unknown bits for some outcome.
    """
    evaluator = _KnownBitsEvaluator(vvar_defs, load_resolver, tmp_defs, fp_compare_leaves)
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
    """Convert `true_set` to a corresponding AIL expression. Returns None if no such expression exists."""
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
    Build the classification test of ``x`` that is exactly true for the fxam outcomes in ``true_set``. This includes
    isnan, isinf, isfinite, isnormal, x == 0, signbit, and the negation of each one of them.
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
    Build the comparison for the CmpF outcomes in ``true_set``.

    Printed FP comparisons are ordered source-level predicates, as IDA prints them: the unordered outcome is folded
    into the comparison (``{LT, UN}`` is ``a < b``, ``{GT, EQ, UN}`` is ``a >= b``) since it only reflects the parity
    check the compiler emits next to the comparison. ``{UN}`` and its complement are NaN tests and stay exact.
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


def fold_fp_logic(
    expr: Expression,
    ail_manager: Manager,
    vvar_defs: dict[int, Expression] | None = None,
    tmp_defs: dict[int, Expression] | None = None,
) -> Expression | None:
    """
    Rebuild a boolean combination of comparisons and NaN tests of one operand pair, e.g. ``a != b ? 1 :
    isunordered(a, b)``, ``a == b && !isunordered(a, b)`` or ``!(a < b || isunordered(a, b))``, as the single ordered
    comparison (see fp_predicate_from_outcomes).

    :return:    The comparison, or None if expr is not such a combination or is a NaN test by itself.
    """
    table = evaluate_over_fsw([expr], vvar_defs, tmp_defs=tmp_defs, fp_compare_leaves=True)
    if table is None or table.source != SOURCE_CMPF or any(vals[0] not in (0, 1) for vals in table.values.values()):
        return None
    true_set = table.true_set(lambda vals: vals[0] == 1)
    ordered = true_set - {CMPF_UN}
    if not ordered or len(ordered) == 3:
        return None
    a, b = table.operands
    tags = expr.tags.copy()
    if expr.bits == 1:
        return fp_predicate_from_outcomes(true_set, (a, b), expr.idx, ail_manager, 1, tags)
    pred = fp_predicate_from_outcomes(true_set, (a, b), ail_manager.next_atom(), ail_manager, 1, tags)
    return Convert(expr.idx, 1, expr.bits, False, pred, **tags)


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


def _strip_fp_widening(expr: Expression) -> Expression:
    while (
        isinstance(expr, Convert)
        and expr.from_type == Convert.TYPE_FP
        and expr.to_type == Convert.TYPE_FP
        and expr.to_bits >= expr.from_bits
    ):
        expr = expr.operand
    return expr


def _const_float(const: Const) -> float | None:
    value = const.value
    if isinstance(value, float):
        return value
    if not isinstance(value, int):
        return None
    # an integer constant compared as a float is a float bit pattern
    if const.bits == 32:
        return struct.unpack("<f", struct.pack("<I", value & 0xFFFF_FFFF))[0]
    if const.bits == 64:
        return struct.unpack("<d", struct.pack("<Q", value & 0xFFFF_FFFF_FFFF_FFFF))[0]
    return None


def fp_operands_match(a: Expression, b: Expression) -> bool:
    """Whether two float comparison operands are the same value, ignoring exact FP widening (float -> double)."""
    a = _strip_fp_widening(a)
    b = _strip_fp_widening(b)
    if isinstance(a, Const) and isinstance(b, Const):
        fa, fb = _const_float(a), _const_float(b)
        return fa is not None and fb is not None and fa == fb
    return a.likes(b)


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
