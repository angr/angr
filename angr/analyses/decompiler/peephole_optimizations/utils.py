from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const


def get_expr_shift_left_amount(expr: BinaryOp) -> int | None:
    """
    Get the shift amount of a shift-left or multiplication operation if the shift amount is a constant.

    :param expr:    The shift-left or multiplication expression (must be a BinaryOp).
    :return:        The shift amount if it is a constant, or None if it is not.
    """
    if expr.op == "Shl" and isinstance(expr.operands[1], Const):
        return expr.operands[1].value
    if expr.op == "Mul" and isinstance(expr.operands[1], Const):
        v = expr.operands[1].value
        if v & (v - 1) == 0:
            return v.bit_length() - 1
    return None
