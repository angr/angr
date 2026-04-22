"""Simplify SSE bitwise conditional select patterns to ITE expressions.

SSE branchless conditional moves use:

    mask = CmpLTV(0, x) ^ 0xFFFF...  (or ~CmpLTV)
    result = (~mask & A) | (B & mask)

This is equivalent to: (condition) ? B : A

This peephole recognizes the pattern and collapses it to an ITE.
"""

from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, ITE, UnaryOp, Extract, VirtualVariable
from angr.ailment.statement import Assignment

from .base import PeepholeOptimizationExprBase


class SSEBitwiseSelect(PeepholeOptimizationExprBase):
    """Collapse SSE bitwise select (andnpd/andpd/orpd) into ITE."""

    __slots__ = ()

    NAME = "SSE bitwise select to ITE"
    expr_classes = (BinaryOp, Extract)

    def optimize(self, expr: BinaryOp | Extract, *, block=None, **kwargs):
        # Build VVar definition map for resolving through temporaries
        vvar_defs: dict[int, object] = {}
        if block is not None:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    vvar_defs[stmt.dst.varid] = stmt.src
        # Handle Extract(Or(...), N@0) -- the 128-bit blend extracted to 64 bits
        inner = expr
        if isinstance(expr, Extract) and expr.is_lsb_extract():
            inner = expr.base

        # Also handle Extract(ITE(...), N@0) -- the ITE may already have been
        # built by a previous peephole run but not yet narrowed.
        if isinstance(inner, ITE) and isinstance(expr, Extract) and inner.bits > expr.bits:
            return self._narrow_ite(inner, expr.bits, expr)

        if not isinstance(inner, BinaryOp) or inner.op != "Or":
            return None

        lhs, rhs = inner.operands

        # Pattern: (~mask & A) | (B & mask)
        # or: (A & ~mask) | (mask & B)
        result = self._match_select(lhs, rhs, vvar_defs)
        if result is None:
            result = self._match_select(rhs, lhs, vvar_defs)
        if result is None:
            return None

        cond_expr, if_true, if_false = result

        ite = ITE(expr.idx, cond_expr, if_false, if_true, **expr.tags)

        # Narrow to target width if the ITE is wider (e.g. 128 -> 64)
        if ite.bits > expr.bits:
            return self._narrow_ite(ite, expr.bits, expr)
        return ite

    @staticmethod
    def _narrow_to(e, out_bits, ref_expr):
        """Narrow expression *e* to *out_bits*, pushing Extract inside UnaryOp."""
        if e.bits <= out_bits:
            return e
        if isinstance(e, UnaryOp) and e.operand.bits > out_bits:
            inner = SSEBitwiseSelect._narrow_to(e.operand, out_bits, ref_expr)
            return UnaryOp(e.idx, e.op, inner, **e.tags)
        off = Const(ref_expr.idx, None, 0, e.bits)
        return Extract(ref_expr.idx, out_bits, e, off, "Iend_LE", **ref_expr.tags)

    @staticmethod
    def _narrow_ite(ite, out_bits, ref_expr):
        """Narrow an ITE and its condition operands to *out_bits*."""
        n = SSEBitwiseSelect._narrow_to
        cond = ite.cond
        if isinstance(cond, BinaryOp) and any(op.bits > out_bits for op in cond.operands):
            narrow_ops = [n(op, out_bits, ref_expr) for op in cond.operands]
            cond = BinaryOp(cond.idx, cond.op, narrow_ops, False, floating_point=cond.floating_point, **cond.tags)
        return ITE(
            ref_expr.idx, cond, n(ite.iffalse, out_bits, ref_expr), n(ite.iftrue, out_bits, ref_expr), **ref_expr.tags
        )

    @staticmethod
    def _match_select(arm_a, arm_b, vvar_defs=None):
        """Try to match arm_a = (~mask & A), arm_b = (B & mask).

        Returns (cond, B, A) if matched, else None.
        """
        vd = vvar_defs or {}

        # arm_a: BitwiseNeg(mask) & A  OR  And(~mask, A)
        neg_mask, val_a = SSEBitwiseSelect._match_negated_and(arm_a)
        if neg_mask is None:
            return None

        underlying_mask = SSEBitwiseSelect._unwrap_negation(neg_mask)
        if underlying_mask is None:
            return None

        # arm_b: And(X, Y) -- one of X, Y should be the same mask
        if not isinstance(arm_b, BinaryOp) or arm_b.op != "And":
            return None

        op0, op1 = arm_b.operands
        if underlying_mask.likes(op0):
            val_b = op1
        elif underlying_mask.likes(op1):
            val_b = op0
        else:
            return None

        # Resolve the mask through VVar definitions to find the CmpF
        resolved_mask = underlying_mask
        if isinstance(resolved_mask, VirtualVariable) and resolved_mask.varid in vd:
            resolved_mask = vd[resolved_mask.varid]

        cond = SSEBitwiseSelect._extract_cond(resolved_mask)
        if cond is None:
            return None

        return cond, val_b, val_a

    @staticmethod
    def _match_negated_and(expr):
        """Match (~X & Y) or (BitwiseNeg(X) & Y). Returns (negated_X_expr, Y)."""
        if not isinstance(expr, BinaryOp) or expr.op != "And":
            return None, None

        lhs, rhs = expr.operands

        # Try lhs = ~X
        if isinstance(lhs, UnaryOp) and lhs.op == "BitwiseNeg":
            return lhs, rhs
        if isinstance(lhs, BinaryOp) and lhs.op == "Xor" and isinstance(lhs.operands[1], Const):
            mask_val = lhs.operands[1].value
            if mask_val == (1 << lhs.bits) - 1:
                return lhs, rhs

        # Try rhs = ~X
        if isinstance(rhs, UnaryOp) and rhs.op == "BitwiseNeg":
            return rhs, lhs
        if isinstance(rhs, BinaryOp) and rhs.op == "Xor" and isinstance(rhs.operands[1], Const):
            mask_val = rhs.operands[1].value
            if mask_val == (1 << rhs.bits) - 1:
                return rhs, lhs

        return None, None

    @staticmethod
    def _unwrap_negation(expr):
        """Given ~X or X ^ 0xFFFF..., return X."""
        if isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg":
            return expr.operand
        if isinstance(expr, BinaryOp) and expr.op == "Xor" and isinstance(expr.operands[1], Const):
            mask_val = expr.operands[1].value
            if mask_val == (1 << expr.bits) - 1:
                return expr.operands[0]
        return None

    @staticmethod
    def _extract_cond(mask_expr):
        """Extract a boolean condition from a CmpF-derived mask.

        The mask is typically: CmpLTV(0, x) ^ 0xFFFF... or similar.
        We look for a CmpF/CmpLTV/CmpLEV at the root.

        The XOR may use a partial all-ones mask (e.g. 0xFFFFFFFFFFFFFFFF
        in a 128-bit field) since SSE comparison results fill only the
        scalar lane.
        """
        expr = mask_expr
        negated = False
        # Peel Xor with all-ones or partial all-ones (negation)
        if isinstance(expr, BinaryOp) and expr.op == "Xor" and isinstance(expr.operands[1], Const):
            val = expr.operands[1].value
            # Accept full all-ones or 64-bit all-ones in wider field
            if val in ((1 << expr.bits) - 1, (1 << 64) - 1, (1 << 32) - 1):
                expr = expr.operands[0]
                negated = True

        # Now expr should be a CmpF variant.  Lower vector comparisons
        # (CmpLTV, CmpGEV, etc.) to scalar (CmpLT, CmpGE) since we're
        # extracting a scalar boolean condition for the ITE.
        vector_to_scalar = {
            "CmpLTV": "CmpLT",
            "CmpLEV": "CmpLE",
            "CmpGTV": "CmpGT",
            "CmpGEV": "CmpGE",
            "CmpEQV": "CmpEQ",
            "CmpNEV": "CmpNE",
        }
        cmp_ops = set(vector_to_scalar.keys())
        if isinstance(expr, BinaryOp) and expr.op in cmp_ops:
            op = expr.op
            if negated:
                negate_map = {
                    "CmpLTV": "CmpGEV",
                    "CmpGEV": "CmpLTV",
                    "CmpLEV": "CmpGTV",
                    "CmpGTV": "CmpLEV",
                    "CmpEQV": "CmpNEV",
                    "CmpNEV": "CmpEQV",
                }
                op = negate_map.get(op, op)
            # Lower to scalar
            scalar_op = vector_to_scalar.get(op, op)
            return BinaryOp(expr.idx, scalar_op, list(expr.operands), False, floating_point=True, **expr.tags)

        return None
