from __future__ import annotations
from angr.ailment.expression import BinaryOp, Convert, Const, ITE

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
    expr_classes = (BinaryOp, Convert)

    def optimize(self, expr: BinaryOp | Convert, **kwargs):

        if isinstance(expr, BinaryOp):
            return self._optimize_BinaryOp(expr)
        if isinstance(expr, Convert):
            return RemoveRedundantBitmasks._optimize_Convert(expr)
        return None

    def _optimize_BinaryOp(self, expr: BinaryOp):
        # And(expr, full_N_bitmask) ==> expr
        # And(SHR(expr, N), bitmask)) ==> SHR(expr, N)
        # And(Conv(1->N, expr), bitmask) ==> Conv(1->N, expr)
        # And(Conv(1->N, bool_expr), bitmask) ==> Conv(1->N, bool_expr)
        # And(ITE(?, const_expr, const_expr), bitmask) ==> ITE(?, const_expr, const_expr)
        if expr.op == "And" and isinstance(expr.operands[1], Const):
            inner_expr = expr.operands[0]
            if expr.operands[1].value == _MASKS.get(inner_expr.bits, None):
                return inner_expr

            if isinstance(inner_expr, BinaryOp) and inner_expr.op == "Shr":
                mask = expr.operands[1]
                shift_val = inner_expr.operands[1]
                if (
                    isinstance(shift_val, Const)
                    and shift_val.value in _MASKS
                    and mask.value == _MASKS.get(int(64 - shift_val.value), None)
                ):
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

    @staticmethod
    def _optimize_Convert(expr: Convert):
        # Conv(64->32, (expr & bitmask) + expr)
        # => Conv(64->32, (expr + expr))
        if (
            expr.op == "Convert"
            and expr.from_bits > expr.to_bits
            and isinstance(expr.operand, BinaryOp)
            and expr.operand.op == "Add"
        ):
            operand_expr = expr.operand
            op0, op1 = operand_expr.operands
            if (
                isinstance(op0, BinaryOp)
                and op0.op == "And"
                and isinstance(op0.operands[1], Const)
                and op0.operands[1].value == _MASKS.get(expr.to_bits, None)
            ):
                new_op0 = op0.operands[0]
                replaced, new_operand_expr = operand_expr.replace(op0, new_op0)
                if replaced:
                    expr.operand = new_operand_expr
                    return expr
        # Conv(64->32, (expr) - (expr) & 0xffffffff<64>)))
        # => Conv(64->32, (expr - expr))
        elif (
            expr.op == "Convert"
            and expr.from_bits > expr.to_bits
            and isinstance(expr.operand, BinaryOp)
            and expr.operand.op == "Sub"
        ):
            operand_expr = expr.operand
            op0, op1 = operand_expr.operands
            if (
                isinstance(op1, BinaryOp)
                and op1.op == "And"
                and isinstance(op1.operands[1], Const)
                and op1.operands[1].value == _MASKS.get(expr.to_bits, None)
            ):
                new_op1 = op1.operands[0]
                replaced, new_operand_expr = operand_expr.replace(op1, new_op1)
                if replaced:
                    expr.operand = new_operand_expr
                    return expr

        return None
