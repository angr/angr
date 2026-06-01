from __future__ import annotations

from angr.ailment.expression import BinaryOp, Convert

from .base import PeepholeOptimizationExprBase


def _is_fp_widening(expr) -> int | None:
    """Return the source bit-width if *expr* is a FP->FP widening Convert, else None."""
    if (
        isinstance(expr, Convert)
        and expr.from_type == expr.to_type == Convert.TYPE_FP
        and expr.from_bits < expr.to_bits
    ):
        return expr.from_bits
    return None


class NarrowFPOperations(PeepholeOptimizationExprBase):
    """
    Narrow floating-point operations when all FP operands are VEX FP
    promotions from the same source width.

    VEX emulates x87 with F64, so float operations appear as::

        AddF64(Conv(32F->64F, a), Conv(32F->64F, b))

    Since both operands are 32-bit floats promoted for emulation, the
    operation is semantically 32-bit.  Narrow to::

        AddF32(a, b)

    """

    __slots__ = ()

    NAME = "Narrow FP operations with promoted float operands"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if not expr.floating_point or len(expr.operands) != 2:
            return None
        w0 = _is_fp_widening(expr.operands[0])
        w1 = _is_fp_widening(expr.operands[1])
        if w0 is None or w1 is None or w0 != w1:
            return None
        # For comparisons (CmpLE etc.), the result is boolean -- keep the
        # original result width.  For arithmetic (Add, Mul etc.), narrow
        # the result to the operand width.
        is_cmp = expr.op.startswith("Cmp")
        return BinaryOp(
            expr.idx,
            expr.op,
            [expr.operands[0].operand, expr.operands[1].operand],
            expr.signed,
            floating_point=True,
            bits=expr.bits if is_cmp else w0,
            **expr.tags,
        )
