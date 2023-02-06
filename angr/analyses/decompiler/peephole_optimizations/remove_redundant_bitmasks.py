from ailment.expression import BinaryOp, Convert, Const, ITE

from .base import PeepholeOptimizationExprBase

_MASKS = {
    8: 0xFF,
    16: 0xFFFF,
    32: 0xFFFFFFFF,
    64: 0xFFFFFFFF_FFFFFFFF,
}


class RemoveRedundantBitmasks(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant bitmasks"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp):
        # And(Conv(M->N, expr), full_N_bitmask) ==> Conv(M->N, expr)
        # And(Conv(1->N, bool_expr), bitmask) ==> Conv(1->N, bool_expr)
        # And(ITE(?, const_expr, const_expr), bitmask) ==> ITE(?, const_expr, const_expr)
        if expr.op == "And" and isinstance(expr.operands[1], Const):
            if isinstance(expr.operands[0], Convert):
                conv_expr = expr.operands[0]
                if expr.operands[1].value == _MASKS.get(conv_expr.to_bits, None):
                    return expr.operands[1]
                if self.is_bool_expr(conv_expr.operand):
                    # useless masking
                    return conv_expr
            if (
                isinstance(expr.operands[0], ITE)
                and isinstance(expr.operands[0].iftrue, Const)
                and isinstance(expr.operands[0].iffalse, Const)
            ):
                # is the masking unnecessary?
                mask = expr.operands[1].value
                ite = expr.operands[0]
                if mask == 0xFF and ite.iftrue.value <= 0xFF and ite.iffalse.value <= 0xFF:
                    # yes!
                    return ite

        return None
