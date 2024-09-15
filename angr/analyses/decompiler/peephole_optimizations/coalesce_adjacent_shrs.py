from __future__ import annotations
from ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class CoalesceAdjacentShiftRights(PeepholeOptimizationExprBase):
    """
    Coalesce adjacent SHR/SAR operations if possible.
    """

    __slots__ = ()

    NAME = "Coalesce adjacent shr/sars"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        # this peephole optimization is probably incorrect...

        if expr.op in {"Sar", "Shr"} and isinstance(expr.operands[1], Const):
            inner = expr.operands[0]
            convert = None
            if isinstance(inner, Convert) and inner.from_bits > inner.to_bits:
                convert = inner
                inner = convert.operand

            if isinstance(inner, BinaryOp) and inner.op == "Shr" and isinstance(inner.operands[1], Const):
                # merge them
                new_shift = inner.operands[1].value + expr.operands[1].value
                r = BinaryOp(
                    expr.idx, expr.op, [inner.operands[0], Const(None, None, new_shift, 8)], expr.signed, **expr.tags
                )
                if convert is not None:
                    return Convert(
                        convert.idx, convert.from_bits, convert.to_bits, convert.is_signed, r, **convert.tags
                    )
                return r

        return None
