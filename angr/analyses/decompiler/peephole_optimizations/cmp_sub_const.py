from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class CmpSubConst(PeepholeOptimizationExprBase):
    """
    Canonicalize equality/inequality comparisons against a constant where one
    side is a constant add/subtract, by folding the inner constant into the
    compared constant. This undoes the compiler's strength-reduced
    ``sub/dec``-cascade lowering of switch-on-value statements, turning relative
    constants back into absolute ones::

        (A - C1) == C2      ==>  A == (C1 + C2)
        (A - C1) != C2      ==>  A != (C1 + C2)
        (C1 - A) == C2      ==>  A == (C1 - C2)
        (A + C1) == C2      ==>  A == (C2 - C1)

    Note that this rule is only applied to ``CmpEQ``/``CmpNE``. Over the modular
    integers ``Z/2^n``, ``A - C1 == C2`` iff ``A == C1 + C2`` and ``A + C1 == C2`` iff
    ``A == C2 - C1`` hold unconditionally, independent of signedness and
    regardless of any intermediate overflow. This rule is NOT applied to ordered
    comparisons (e.g., ``CmpLT``), for which folding across a subtract is unsound
    because of wraparound.
    """

    __slots__ = ()

    NAME = "(A - C1) cmp C2 => A cmp (C1 + C2)"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in ("CmpEQ", "CmpNE"):
            return None

        op0, op1 = expr.operands
        # Normalize so the compared constant is cmp_const and the arithmetic
        # expression is arith.
        if isinstance(op1, Const) and op1.is_int and isinstance(op0, BinaryOp):
            arith, cmp_const = op0, op1
        elif isinstance(op0, Const) and op0.is_int and isinstance(op1, BinaryOp):
            arith, cmp_const = op1, op0
        else:
            return None

        if arith.op not in ("Add", "Sub"):
            return None

        a0, a1 = arith.operands
        bits = arith.bits
        if cmp_const.bits != bits:
            return None
        mask = (1 << bits) - 1
        d = cmp_const.value_int & mask

        # Determine the variable side (var) and the folded constant (new_val).
        if arith.op == "Add":
            # a0 + a1 == d  ==>  var == d - k
            if isinstance(a1, Const) and a1.is_int and not isinstance(a0, Const):
                var, k = a0, a1.value_int
            elif isinstance(a0, Const) and a0.is_int and not isinstance(a1, Const):
                var, k = a1, a0.value_int
            else:
                return None
            new_val = (d - k) & mask
        else:  # Sub
            if isinstance(a1, Const) and a1.is_int and not isinstance(a0, Const):
                # a0 - k == d  ==>  a0 == d + k
                var, k = a0, a1.value_int
                new_val = (d + k) & mask
            elif isinstance(a0, Const) and a0.is_int and not isinstance(a1, Const):
                # k - a1 == d  ==>  a1 == k - d
                var, k = a1, a0.value_int
                new_val = (k - d) & mask
            else:
                return None

        if var.bits != bits:
            return None

        new_const = Const(self.manager.next_atom(), new_val, bits, **cmp_const.tags)
        return BinaryOp(
            expr.idx,
            expr.op,
            (var, new_const),
            expr.signed,
            bits=expr.bits,
            floating_point=expr.floating_point,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )
