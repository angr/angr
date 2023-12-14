# pylint:disable=too-many-boolean-expressions
from typing import Optional, Dict, Tuple
from ailment.expression import Expression, BinaryOp, Const, Convert, ITE

from .base import PeepholeOptimizationExprBase


class RewriteBitExtractions(PeepholeOptimizationExprBase):
    """
    Rewrite bit extraction expressions
    """

    __slots__ = ()

    NAME = "Bit-extraction Rewriter"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op == "And" and isinstance(expr.operands[1], Const) and expr.operands[1].value == 1:
            raw_expr = expr.operands[0]
            bit_offset = 0
            if isinstance(raw_expr, BinaryOp) and raw_expr.op == "Shr" and isinstance(raw_expr.operands[1], Const):
                bit_offset += raw_expr.operands[1].value
                raw_expr = raw_expr.operands[0]

            # we try to expand raw_expr into a mapping between bit_offset and 1-bit expressions
            bitoffset2exprs = self._extract_bitoffset_to_expr_mapping(raw_expr)
            if bitoffset2exprs is not None and bit_offset in bitoffset2exprs:
                return ITE(
                    expr.idx,
                    bitoffset2exprs[bit_offset],
                    Const(None, None, 1, expr.bits),
                    Const(None, None, 0, expr.bits),
                    **expr.tags,
                )

        return None

    def _extract_bitoffset_to_expr_mapping(self, expr: BinaryOp) -> Optional[Dict[int, Expression]]:
        d = {}
        if isinstance(expr, BinaryOp) and expr.op == "Or":
            for arg in expr.operands:
                r = self._get_setbit(arg)
                if r is not None:
                    setbit, inner_expr = r
                    if setbit in d:
                        # failed!
                        return None
                    d[setbit] = inner_expr
                else:
                    d_ = self._extract_bitoffset_to_expr_mapping(arg)
                    if d_ is None:
                        # failed!
                        return None
                    if set(d_.keys()).intersection(d.keys()):
                        # a bit is set multiple times..,
                        return None
                    d.update(d_)
        if not d:
            return None
        return d

    @staticmethod
    def _get_setbit(expr: Expression) -> Optional[Tuple[int, Expression]]:
        """
        Test if expr is a single-bit expression, and if it is, return the bit offset that it sets and the inner
        expression that sets the bit.

        :param expr:    The expression
        """

        if isinstance(expr, BinaryOp):
            if expr.op == "And":
                if isinstance(expr.operands[1], Const) and expr.operands[1].value == 1:
                    return 0, expr
            if expr.op == "Shl" and isinstance(expr.operands[1], Const):
                offset = expr.operands[1].value
                r = RewriteBitExtractions._get_setbit(expr.operands[0])
                if r is not None:
                    setbit = r[0] + offset
                    return setbit, r[1]
        if isinstance(expr, Convert) and expr.from_bits == 1 and not expr.is_signed:
            return 0, expr.operand
        if expr.bits == 1:
            return 0, expr
        return None
