from ailment.expression import BinaryOp, Convert, Const, ITE

from .base import PeepholeOptimizationExprBase

_MASKS = {
    1: 1,
    8: 0xFF,
    16: 0xFFFF,
    32: 0xFFFFFFFF,
    64: 0xFFFFFFFF_FFFFFFFF,
}


class RemoveRedundantBitmasks(PeepholeOptimizationExprBase):
    """
    Remove redundant bitmasking operations.
    """

    __slots__ = ()

    NAME = "Remove redundant bitmasks"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        # And(expr, full_N_bitmask) ==> expr
        # And(Conv(1->N, expr), bitmask) ==> Conv(1->N, expr)
        # And(Conv(1->N, bool_expr), bitmask) ==> Conv(1->N, bool_expr)
        # And(ITE(?, const_expr, const_expr), bitmask) ==> ITE(?, const_expr, const_expr)
        if expr.op == "And" and isinstance(expr.operands[1], Const):
            inner_expr = expr.operands[0]
            if expr.operands[1].value == _MASKS.get(inner_expr.bits, None):
                return inner_expr
            if isinstance(inner_expr, Convert) and self.is_bool_expr(inner_expr.operand):
                # useless masking
                return inner_expr
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
