from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase
from .bool_scaled_mask import _int_const, scaled_bool
from .known_bits import block_defs_resolver, known_bits


def _or_terms(expr: Expression) -> list[Expression]:
    """The operands of a (nested) bitwise OR."""
    if (
        isinstance(expr, BinaryOp)
        and expr.op == "Or"
        and not expr.floating_point
        and all(op.bits == expr.bits for op in expr.operands)
    ):
        return [t for op in expr.operands for t in _or_terms(op)]
    return [expr]


class MaskedBoolOrCmpZero(PeepholeOptimizationExprBase):
    """
    A flags word tested against a mask, where the word is an OR of booleans scaled to distinct bits:

        ((zext(b0) << k0 | zext(b1) << k1 | ...) & M) != 0  ==>  b_i || b_j || ...
        ((zext(b0) << k0 | zext(b1) << k1 | ...) & M) == 0  ==>  !b_i && !b_j && ...

    for the terms whose bit is in ``M``. A term that is not a scaled boolean must have every bit of ``M`` known zero.
    """

    __slots__ = ()

    NAME = "(OR of scaled booleans & M) cmp 0 => OR of the selected booleans"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, block_defs=None, **kwargs):
        if expr.op not in {"CmpEQ", "CmpNE"} or expr.floating_point:
            return None
        op0, op1 = expr.operands
        if _int_const(op0) == 0:
            op0, op1 = op1, op0
        if _int_const(op1) != 0:
            return None
        bits = op0.bits
        full = (1 << bits) - 1
        mask = full
        word = op0
        if isinstance(op0, BinaryOp) and op0.op == "And" and not op0.floating_point:
            for value, m in (op0.operands, op0.operands[::-1]):
                if (mv := _int_const(m)) is not None and value.bits == bits:
                    word, mask = value, mv & full
                    break
            else:
                return None
        terms = _or_terms(word)
        if len(terms) < 2:
            return None

        resolver = None
        selected: list[Expression] = []
        for term in terms:
            sb = scaled_bool(term)
            if sb is not None:
                b, k, negated = sb
                if not (mask >> k) & 1:
                    continue
                if b.bits != 1:
                    return None
                selected.append((b, negated))
                continue
            if resolver is None:
                resolver = block_defs_resolver(block_defs)
            zeros, _ = known_bits(term, resolver, tmps=block_defs.tmps if block_defs is not None else None)
            if zeros & mask != mask:
                return None

        if not selected:
            return Const(expr.idx, 1 if expr.op == "CmpEQ" else 0, 1, **expr.tags)
        test_true = expr.op == "CmpNE"
        conds = []
        for b, negated in selected:
            # the term's bit is set iff b ^ negated
            if negated == test_true:
                conds.append(UnaryOp(self.manager.next_atom(), "Not", b, bits=1, **b.tags))
            else:
                conds.append(b)
        out = conds[0]
        for c in conds[1:]:
            out = BinaryOp(
                self.manager.next_atom(), "LogicalOr" if test_true else "LogicalAnd", [out, c], False, bits=1
            )
        if len(conds) == 1:
            return out if out.bits == expr.bits else None
        return BinaryOp(expr.idx, out.op, list(out.operands), False, bits=expr.bits, **expr.tags)
