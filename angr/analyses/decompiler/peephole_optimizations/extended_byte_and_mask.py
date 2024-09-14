from __future__ import annotations
from ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase

_MASK_TO_BITS = {
    0xFF: 8,
    0xFFFF: 16,
    0xFFFF_FFFF: 32,
}


class ExtendedByteAndMask(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "extended byte & 0xff..ff => extended byte"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        #
        if expr.op == "And" and isinstance(expr.operands[1], Const):
            mask = expr.operands[1].value
            to_bits = _MASK_TO_BITS.get(mask)
            if to_bits is None:
                return None

            if isinstance(expr.operands[0], Convert):
                conv: Convert = expr.operands[0]
                atom = conv.operand
                if conv.from_bits <= to_bits:
                    # this masking is useless
                    return Convert(None, conv.from_bits, expr.bits, conv.is_signed, atom, **conv.tags)

            elif (
                isinstance(expr.operands[0], BinaryOp)
                and expr.operands[0].op in {"Shl", "Shr", "Sar"}
                and isinstance(expr.operands[0].operands[0], Convert)
            ):
                binop_expr = expr.operands[0]
                conv: Convert = expr.operands[0].operands[0]
                atom = conv.operand
                if conv.from_bits <= to_bits:
                    # this masking is useless
                    # apply the binary operation
                    atom = BinaryOp(
                        None,
                        binop_expr.op,
                        (atom, binop_expr.operands[1]),
                        binop_expr.signed,
                        variable=binop_expr.variable,
                        variable_offset=binop_expr.variable_offset,
                        **binop_expr.tags,
                    )
                    return Convert(None, conv.from_bits, expr.bits, conv.is_signed, atom, **conv.tags)

        return None
