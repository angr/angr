from ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase

_MASK_TO_BITS = {
    0xff: 8,
    0xffff: 16,
    0xffff_ffff: 32,
}


class ExtendedByteAndMask(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "extended byte & 0xff..ff => extended byte"
    expr_classes = (BinaryOp, )  # all expressions are allowed

    def optimize(self, expr: BinaryOp):

        #
        if expr.op == "And" \
                and isinstance(expr.operands[1], Const):
            mask = expr.operands[1].value
            to_bits = _MASK_TO_BITS.get(mask, None)
            if to_bits is None:
                return None

            if isinstance(expr.operands[0], Convert):
                conv: Convert = expr.operands[0]
                atom = conv.operand
                if conv.from_bits <= to_bits:
                    # this masking is useless
                    return Convert(None, conv.from_bits, expr.bits, conv.is_signed, atom, **conv.tags)

            elif isinstance(expr.operands[0], BinaryOp) and expr.operands[0].op in {'Shl', 'Shr', 'Sar'} \
                    and isinstance(expr.operands[0].operands[0], Convert):
                binop_expr = expr.operands[0]
                conv: Convert = expr.operands[0].operands[0]
                atom = conv.operand
                if conv.from_bits <= to_bits:
                    # this masking is useless
                    # apply the binary operation
                    atom = BinaryOp(None, binop_expr.op, (atom, binop_expr.operands[1]), binop_expr.signed,
                                    variable=binop_expr.variable,
                                    variable_offset=binop_expr.variable_offset,
                                    **binop_expr.tags
                                    )
                    return Convert(None, conv.from_bits, expr.bits, conv.is_signed, atom, **conv.tags)

        return None
