from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert
from angr.utils.bits import sign_extend


def evaluate_const_int_conversion(expr: Convert) -> int | None:
    """Evaluate an integer ``Convert`` whose operand is an integer constant."""

    operand = expr.operand
    if (
        not isinstance(operand, Const)
        or not isinstance(operand.value, int)
        or expr.from_type != Convert.TYPE_INT
        or expr.to_type != Convert.TYPE_INT
    ):
        return None

    # AIL constants may be represented as either signed Python integers or unsigned bit patterns. Normalize the
    # operand at its *source* width before extending it; testing the destination sign bit would turn a signed
    # widening conversion such as 0x8000:s16 -> s32 into 0x00008000.
    value = operand.value & ((1 << expr.from_bits) - 1)
    if expr.is_signed:
        value = sign_extend(value, expr.from_bits)

    value &= (1 << expr.to_bits) - 1
    if expr.is_signed:
        value = sign_extend(value, expr.to_bits)
    return value


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
