from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Extract, Insert, ITE, VirtualVariable
from angr.ailment.statement import Assignment

from .base import PeepholeOptimizationExprBase


class X86CmpF(PeepholeOptimizationExprBase):
    """
    Simplifies x86/x87 CmpF status word bit extractions into readable comparison operators.

    x87 CmpF returns a 32-bit status word:
      0x00 = GT, 0x01 = LT, 0x40 = EQ, 0x45 = Unordered

    GCC emits bit manipulation patterns to extract the comparison result. This peephole
    matches those patterns and replaces them with CmpGT, CmpLE, or CmpEQ.
    """

    __slots__ = ()

    NAME = "Simplifying CmpF on x86"
    expr_classes = (BinaryOp, ITE)

    def optimize(self, expr: BinaryOp | ITE, *, block=None, **kwargs):
        # Build a VirtualVariable -> definition map so pattern matchers can
        # see through Tmp/VVar indirections (common on AMD64 where CmpF
        # results are assigned to temporaries before bit manipulation).
        vvar_defs: dict[int, object] = {}
        if block is not None:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    vvar_defs[stmt.dst.varid] = stmt.src
        if isinstance(expr, ITE):
            return self._optimize_ite(expr, vvar_defs)
        return self._optimize_binop(expr, vvar_defs)

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
        if not (
            isinstance(cond, BinaryOp)
            and cond.op == "CmpEQ"
            and isinstance(cond.operands[1], Const)
            and cond.operands[1].value == 0
        ):
            return None

        # Check if iftrue is 0
        if not (isinstance(expr.iftrue, Const) and expr.iftrue.value == 0):
            return None

        # Match condition operand: (CmpF & 0x45) >> 6 & 1
        # The operand may be wrapped in Extract(8@0) from narrowing Convert peeling.
        cond_operand = cond.operands[0]
        if isinstance(cond_operand, Extract) and cond_operand.is_lsb_extract():
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
            elif isinstance(iffalse, Insert) and iffalse.is_lsb_overwrite():
                iffalse = iffalse.value
            elif isinstance(iffalse, Extract) and iffalse.is_lsb_extract():
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

    def _optimize_binop(self, expr: BinaryOp, vvar_defs: dict | None = None):
        vd = vvar_defs or {}
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

        return None

    @staticmethod
    def _match_not_gt_pattern(expr, vvar_defs: dict | None = None):
        """
        Match: (CmpF(a,b) & 0x45 | (CmpF(a,b) & 0x45) >> 6) & 1

        Returns the CmpF operands (a, b) if matched, else None.
        """
        vd = vvar_defs or {}
        _r = X86CmpF._resolve
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
        result = X86CmpF._match_masked_and_shifted(masked, shifted, vd)
        if result is None:
            result = X86CmpF._match_masked_and_shifted(shifted, masked, vd)
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
        cmpf_ops_masked = X86CmpF._match_masked_cmpf(masked, 0x45, vd)
        if cmpf_ops_masked is None:
            return None

        # Unwrap Convert if present (e.g. 32->8 truncation on AMD64)
        if isinstance(shifted, Convert):
            shifted = X86CmpF._resolve(shifted.operand, vd)
        if not (
            isinstance(shifted, BinaryOp)
            and shifted.op == "Shr"
            and isinstance(shifted.operands[1], Const)
            and shifted.operands[1].value == 6
        ):
            return None

        cmpf_ops_shifted = X86CmpF._match_masked_cmpf(shifted.operands[0], 0x45, vd)
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
        expr = X86CmpF._resolve(expr, vd)
        # Unwrap Convert (widening or narrowing -- CmpF is 32-bit but may be
        # sign/zero-extended to 64-bit on AMD64 or truncated to 8-bit)
        if isinstance(expr, Convert):
            expr = X86CmpF._resolve(expr.operand, vd)
        if not (
            isinstance(expr, BinaryOp)
            and expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == mask
        ):
            return None

        cmpf = X86CmpF._resolve(expr.operands[0], vd)
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

        return X86CmpF._match_masked_cmpf(shifted.operands[0], mask)

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
        return X86CmpF._match_masked_cmpf(expr.operands[0], inner_mask)
