from __future__ import annotations

from typing import NamedTuple

from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Convert,
    Expression,
    Extract,
    Insert,
    Tmp,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment
from angr.ailment.utils import is_lsb_extract, is_lsb_overwrite
from angr.analyses.decompiler.x87_fsw import (
    LoadResolver,
    const_is_nan,
    evaluate_over_fsw,
    fsw_predicate,
    store_forwarder,
)

from .base import PeepholeOptimizationExprBase


class _FswContext(NamedTuple):
    """Block context for evaluating status-word tests: Tmp definitions and earlier stores."""

    tmp_defs: dict[int, Expression]
    load_resolver: LoadResolver | None


class X87CmpF(PeepholeOptimizationExprBase):
    """
    Simplifies x87 CmpF status word bit extractions into readable comparison operators.

    x87 CmpF returns a 32-bit status word:
      0x00 = GT, 0x01 = LT, 0x40 = EQ, 0x45 = Unordered

    GCC emits bit manipulation patterns to extract the comparison result. This peephole
    matches those patterns and replaces them with CmpGT, CmpLE, or CmpEQ.
    """

    __slots__ = ()

    NAME = "Simplifying CmpF on x87"
    expr_classes = (BinaryOp, ITE, UnaryOp)

    def optimize(self, expr: BinaryOp | ITE | UnaryOp, *, stmt_idx: int | None = None, block=None, **kwargs):
        if isinstance(expr, UnaryOp):
            # IsNaN(const) once a constant operand has been propagated in
            if expr.op == "IsNaN" and isinstance(expr.operand, Const):
                return Const(expr.idx, 1 if const_is_nan(expr.operand) else 0, expr.bits, **expr.tags)
            return None
        # Build a VirtualVariable -> definition map so pattern matchers can
        # see through Tmp/VVar indirections (common on AMD64 where CmpF
        # results are assigned to temporaries before bit manipulation).
        vvar_defs: dict[int, object] = {}
        tmp_defs: dict[int, Expression] = {}
        if block is not None:
            for stmt in block.statements:
                if isinstance(stmt, Assignment):
                    if isinstance(stmt.dst, VirtualVariable):
                        vvar_defs[stmt.dst.varid] = stmt.src
                    elif isinstance(stmt.dst, Tmp):
                        tmp_defs[stmt.dst.tmp_idx] = stmt.src
        if isinstance(expr, ITE):
            return self._optimize_ite(expr, vvar_defs)
        load_resolver = (
            store_forwarder(block.statements, stmt_idx) if block is not None and stmt_idx is not None else None
        )
        return self._optimize_binop(expr, vvar_defs, _FswContext(tmp_defs, load_resolver))

    @staticmethod
    def _resolve(expr, vvar_defs: dict, depth: int = 3):
        """Resolve VirtualVariable references through their definitions."""
        while depth > 0 and isinstance(expr, VirtualVariable) and expr.varid in vvar_defs:
            expr = vvar_defs[expr.varid]
            depth -= 1
        return expr

    def _optimize_ite(self, expr: ITE, vvar_defs: dict | None = None):
        # Pattern: ITE((CmpF & 0x45) >> 6 & 1 == 0, 0, !((CmpF & 0x45) >> 2 & 1))
        # This is GCC's IEEE 754 equality: true iff equal AND not unordered.
        # Match condition: bit6_expr == 0
        cond = expr.cond
        if not (isinstance(expr.iftrue, Const) and expr.iftrue.value == 0):
            return None
        if isinstance(cond, BinaryOp) and cond.op == "CmpNE" and cond.floating_point:
            # the two bit tests were already folded: ITE(a != b, 0, !(isnan(a) || isnan(b)))
            a, b = cond.operands
            if self._is_ordered_check(expr.iffalse, a, b, vvar_defs or {}):
                return BinaryOp(expr.idx, "CmpEQ", [a, b], False, floating_point=True, bits=8, **expr.tags)
            return None
        if not (
            isinstance(cond, BinaryOp)
            and cond.op == "CmpEQ"
            and isinstance(cond.operands[1], Const)
            and cond.operands[1].value == 0
        ):
            return None

        # Match condition operand: (CmpF & 0x45) >> 6 & 1
        # The operand may be wrapped in Extract(8@0) from narrowing Convert peeling.
        cond_operand = cond.operands[0]
        if isinstance(cond_operand, Extract) and is_lsb_extract(cond_operand):
            cond_operand = cond_operand.base
        bit6_cmpf = self._match_bit_extraction(cond_operand, mask=0x45, shift=6)
        if bit6_cmpf is None:
            return None

        # Match iffalse: Conv(1I->32I, (CmpF & 0x45) >> 2 & 1 == 0)
        # or Insert(0, 0, ...) (AMD64 O0 zero-extension of 8-bit setnp result)
        # or directly: (CmpF & 0x45) >> 2 & 1 == 0
        iffalse = expr.iffalse
        # Peel through Convert (widening or narrowing) and Insert(0, 0, ...)
        # wrappers.  AMD64 O0 can produce Conv(64->32, Insert(0, 0, Conv(1->8, ...))).
        for _ in range(4):
            if isinstance(iffalse, Convert):
                iffalse = iffalse.operand
            elif isinstance(iffalse, Insert) and is_lsb_overwrite(iffalse):
                iffalse = iffalse.value
            elif isinstance(iffalse, Extract) and is_lsb_extract(iffalse):
                iffalse = iffalse.base
            else:
                break

        # iffalse should be: ((CmpF & 0x45) >> 2 & 1) == 0
        if not (
            isinstance(iffalse, BinaryOp)
            and iffalse.op == "CmpEQ"
            and isinstance(iffalse.operands[1], Const)
            and iffalse.operands[1].value == 0
        ):
            return None

        bit2_cmpf = self._match_bit_extraction(iffalse.operands[0], mask=0x45, shift=2)
        if bit2_cmpf is None:
            # AMD64 ccall rewriter produces (CmpF & 0x45 & 4) instead of (CmpF & 0x45) >> 2 & 1
            bit2_cmpf = self._match_double_masked_cmpf(iffalse.operands[0], outer_mask=0x4, inner_mask=0x45)
        if bit2_cmpf is None:
            return None

        # Both must reference the same CmpF operands
        if not (bit6_cmpf[0].likes(bit2_cmpf[0]) and bit6_cmpf[1].likes(bit2_cmpf[1])):
            return None

        # Match! Replace with CmpEQ
        # Use 8 bits to match the Extract(8bits@0) that typically wraps this.
        return BinaryOp(expr.idx, "CmpEQ", list(bit6_cmpf), False, floating_point=True, bits=8, **expr.tags)

    @staticmethod
    def _is_ordered_check(expr, a, b, vvar_defs: dict) -> bool:
        """Match !isunordered(a, b) (or !isnan(a) when a and b are the same) through value-preserving wrappers."""
        for _ in range(6):
            expr = X87CmpF._resolve(expr, vvar_defs)
            if isinstance(expr, Convert):
                expr = expr.operand
            elif isinstance(expr, Insert) and is_lsb_overwrite(expr):
                expr = expr.value
            elif isinstance(expr, Extract) and is_lsb_extract(expr):
                expr = expr.base
            elif (
                isinstance(expr, BinaryOp)
                and expr.op == "And"
                and isinstance(expr.operands[1], Const)
                and expr.operands[1].value == 1
            ):
                expr = expr.operands[0]
            else:
                break
        if not (isinstance(expr, UnaryOp) and expr.op == "Not"):
            return False
        inner = X87CmpF._resolve(expr.operand, vvar_defs)
        if isinstance(inner, BinaryOp) and inner.op == "CmpUN":
            return inner.operands[0].likes(a) and inner.operands[1].likes(b)
        if isinstance(inner, UnaryOp) and inner.op == "IsNaN":
            return inner.operand.likes(a) or inner.operand.likes(b)
        return False

    def _optimize_binop(self, expr: BinaryOp, vvar_defs: dict | None = None, ctx: _FswContext | None = None):
        vd = vvar_defs or {}
        if expr.op == "CmpUN":
            if expr.operands[0].likes(expr.operands[1]):
                # isunordered(x, x) -> isnan(x) once both operands resolved to the same value
                return UnaryOp(expr.idx, "IsNaN", expr.operands[0], bits=expr.bits, **expr.tags)
            # isunordered(const, x) -> isnan(x) once a constant operand has been propagated in
            consts = [isinstance(op, Const) and not const_is_nan(op) for op in expr.operands]
            if all(consts):
                return Const(expr.idx, 0, expr.bits, **expr.tags)
            if any(consts):
                other = expr.operands[0] if consts[1] else expr.operands[1]
                return UnaryOp(expr.idx, "IsNaN", other, bits=expr.bits, **expr.tags)
            return None
        # Pattern 1: ((CmpF(a,b) & 0x45 | (CmpF(a,b) & 0x45) >> 6) & 1) == 1
        #   This tests "NOT GT" (i.e., LE including unordered).
        #   == 1 -> CmpLE,  == 0 / != 1 -> CmpGT
        if expr.op in ("CmpEQ", "CmpNE") and isinstance(expr.operands[1], Const):
            const_val = expr.operands[1].value
            inner = expr.operands[0]
            cmpf_operands = self._match_not_gt_pattern(inner, vd)
            if cmpf_operands is not None and all(hasattr(op, "bits") and op.bits for op in cmpf_operands):
                is_le = (expr.op == "CmpEQ" and const_val == 1) or (expr.op == "CmpNE" and const_val == 0)
                is_gt = (expr.op == "CmpEQ" and const_val == 0) or (expr.op == "CmpNE" and const_val == 1)
                if is_le:
                    return BinaryOp(expr.idx, "CmpLE", list(cmpf_operands), False, floating_point=True, **expr.tags)
                if is_gt:
                    return BinaryOp(expr.idx, "CmpGT", list(cmpf_operands), False, floating_point=True, **expr.tags)

        # Pattern 2: (CmpF(a,b) & 0x45) == 0  ->  CmpGT
        # Pattern 3: (CmpF(a,b) & 0x45) != 0  ->  CmpLE
        if expr.op in ("CmpEQ", "CmpNE") and isinstance(expr.operands[1], Const) and expr.operands[1].value == 0:
            cmpf_operands = self._match_masked_cmpf(expr.operands[0], 0x45, vd)
            if cmpf_operands is not None:
                if expr.op == "CmpEQ":
                    return BinaryOp(expr.idx, "CmpGT", list(cmpf_operands), False, floating_point=True, **expr.tags)
                return BinaryOp(expr.idx, "CmpLE", list(cmpf_operands), False, floating_point=True, **expr.tags)

        # Pattern 4: (CmpF(a,b) & 0x45) == 0x40  ->  CmpEQ
        # Pattern 5: (CmpF(a,b) & 0x45) != 0x40  ->  CmpNE
        if expr.op in ("CmpEQ", "CmpNE") and isinstance(expr.operands[1], Const) and expr.operands[1].value == 0x40:
            cmpf_operands = self._match_masked_cmpf(expr.operands[0], 0x45, vd)
            if cmpf_operands is not None:
                op = "CmpEQ" if expr.op == "CmpEQ" else "CmpNE"
                return BinaryOp(expr.idx, op, list(cmpf_operands), False, floating_point=True, **expr.tags)

        return self._optimize_by_evaluation(expr, vd, ctx or _FswContext({}, None))

    def _optimize_by_evaluation(self, expr: BinaryOp, vvar_defs: dict, ctx: _FswContext) -> Expression | None:
        """
        Evaluate the expression for each CmpF or fxam outcome (sees through fnstsw/sahf bit shuffling) and rebuild it
        as a comparison or classification test when it is a test against a constant or a 0/1-valued bit test.
        """
        if expr.op in ("CmpEQ", "CmpNE"):
            if not (isinstance(expr.operands[1], Const) and isinstance(expr.operands[1].value, int)):
                return None
            table = evaluate_over_fsw([expr.operands[0]], vvar_defs, ctx.load_resolver, ctx.tmp_defs)
            if table is None:
                return None
            const_val = expr.operands[1].value
            true_set = table.true_set(lambda vals: (vals[0] == const_val) == (expr.op == "CmpEQ"))
            return fsw_predicate(table, true_set, expr.idx, self.manager, expr.bits, expr.tags)

        if expr.op == "And" and isinstance(expr.operands[1], Const) and expr.operands[1].value in (1, 4, 0x40):
            table = evaluate_over_fsw([expr], vvar_defs, ctx.load_resolver, ctx.tmp_defs)
            if table is None or any(vals[0] not in (0, 1) for vals in table.values.values()):
                return None
            true_set = table.true_set(lambda vals: vals[0] == 1)
            if expr.bits == 1:
                return fsw_predicate(table, true_set, expr.idx, self.manager, 1, expr.tags)
            pred = fsw_predicate(table, true_set, self.manager.next_atom(), self.manager, 1, expr.tags)
            if pred is None:
                return None
            return Convert(expr.idx, 1, expr.bits, False, pred, **expr.tags)

        return None

    @staticmethod
    def _match_not_gt_pattern(expr, vvar_defs: dict | None = None):
        """
        Match: (CmpF(a,b) & 0x45 | (CmpF(a,b) & 0x45) >> 6) & 1

        Returns the CmpF operands (a, b) if matched, else None.
        """
        vd = vvar_defs or {}
        _r = X87CmpF._resolve
        # Outer: And(..., 1)
        if not (
            isinstance(expr, BinaryOp)
            and expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == 1
        ):
            return None

        or_expr = _r(expr.operands[0], vd)
        # Or(masked, Shr(masked, 6))
        if not (isinstance(or_expr, BinaryOp) and or_expr.op == "Or"):
            return None

        masked = _r(or_expr.operands[0], vd)
        shifted = _r(or_expr.operands[1], vd)

        # Try both orderings: Or(masked, shifted) and Or(shifted, masked)
        result = X87CmpF._match_masked_and_shifted(masked, shifted, vd)
        if result is None:
            result = X87CmpF._match_masked_and_shifted(shifted, masked, vd)
        if result is None:
            return None

        cmpf_ops_left, cmpf_ops_right = result

        # Both sides must reference the same CmpF operands
        if not (cmpf_ops_left[0].likes(cmpf_ops_right[0]) and cmpf_ops_left[1].likes(cmpf_ops_right[1])):
            return None

        return cmpf_ops_left

    @staticmethod
    def _match_masked_and_shifted(masked, shifted, vvar_defs: dict | None = None):
        """Match (CmpF & 0x45) as masked and Shr(CmpF & 0x45, 6) as shifted.

        The shifted operand may be wrapped in a Convert (truncation) on AMD64.
        Returns (cmpf_ops_masked, cmpf_ops_shifted) or None.
        """
        vd = vvar_defs or {}
        cmpf_ops_masked = X87CmpF._match_masked_cmpf(masked, 0x45, vd)
        if cmpf_ops_masked is None:
            return None

        # Unwrap Convert if present (e.g. 32->8 truncation on AMD64)
        if isinstance(shifted, Convert):
            shifted = X87CmpF._resolve(shifted.operand, vd)
        if not (
            isinstance(shifted, BinaryOp)
            and shifted.op == "Shr"
            and isinstance(shifted.operands[1], Const)
            and shifted.operands[1].value == 6
        ):
            return None

        cmpf_ops_shifted = X87CmpF._match_masked_cmpf(shifted.operands[0], 0x45, vd)
        if cmpf_ops_shifted is None:
            return None

        return cmpf_ops_masked, cmpf_ops_shifted

    @staticmethod
    def _match_masked_cmpf(expr, mask, vvar_defs: dict | None = None):
        """
        Match: CmpF(a, b) & mask

        The expression may be wrapped in a Convert (truncation) on AMD64.
        Returns (a, b) if matched, else None.
        """
        vd = vvar_defs or {}
        expr = X87CmpF._resolve(expr, vd)
        # Unwrap Convert (widening or narrowing -- CmpF is 32-bit but may be
        # sign/zero-extended to 64-bit on AMD64 or truncated to 8-bit)
        if isinstance(expr, Convert):
            expr = X87CmpF._resolve(expr.operand, vd)
        if not (
            isinstance(expr, BinaryOp)
            and expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == mask
        ):
            return None

        cmpf = X87CmpF._resolve(expr.operands[0], vd)
        if isinstance(cmpf, BinaryOp) and cmpf.op == "CmpF":
            return cmpf.operands

        return None

    @staticmethod
    def _match_bit_extraction(expr, mask, shift):
        """
        Match: (CmpF(a, b) & mask) >> shift & 1

        Returns the CmpF operands (a, b) if matched, else None.
        """
        # Outer: And(..., 1)
        if not (
            isinstance(expr, BinaryOp)
            and expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == 1
        ):
            return None

        shifted = expr.operands[0]
        # Shr(CmpF & mask, shift)
        if not (
            isinstance(shifted, BinaryOp)
            and shifted.op == "Shr"
            and isinstance(shifted.operands[1], Const)
            and shifted.operands[1].value == shift
        ):
            return None

        return X87CmpF._match_masked_cmpf(shifted.operands[0], mask)

    @staticmethod
    def _match_double_masked_cmpf(expr, outer_mask, inner_mask):
        """
        Match: (CmpF(a, b) & inner_mask) & outer_mask

        This is the AMD64 ccall-rewritten form of the bit extraction
        that i386 expresses as (CmpF & inner_mask) >> shift & 1.
        Returns (a, b) if matched, else None.
        """
        if not (
            isinstance(expr, BinaryOp)
            and expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == outer_mask
        ):
            return None
        return X87CmpF._match_masked_cmpf(expr.operands[0], inner_mask)
