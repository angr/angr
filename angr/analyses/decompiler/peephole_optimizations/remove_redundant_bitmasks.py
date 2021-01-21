from ailment.expression import BinaryOp, Convert, Const

from .base import PeepholeOptimizationExprBase

_MASKS = {
    8: 0xff,
    16: 0xffff,
    32: 0xffffffff,
    64: 0xffffffff_ffffffff,
}


class RemoveRedundantBitmasks(PeepholeOptimizationExprBase):
    __slots__ = ()

    name = "Remove redundant bitmasks"
    expr_classes = (BinaryOp, )  # all expressions are allowed

    def optimize(self, expr: BinaryOp):

        # And(Conv(M->N, expr), full_N_bitmask) ==> Conv(M->N, expr)
        # And(Conv(1->N, bool_expr), bitmask) ==> Conv(1->N, bool_expr)
        if expr.op == "And" \
                and isinstance(expr.operands[0], Convert) \
                and isinstance(expr.operands[1], Const):
            conv_expr = expr.operands[0]
            if expr.operands[1].value == _MASKS.get(conv_expr.to_bits, None):
                return expr.operands[1]
            if self.is_bool_expr(conv_expr.operand):
                # useless masking
                return conv_expr

        return None
