from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase
from .vm_bool_select import same_value

_MAX_DEPTH = 16

# bit j of an expression: a constant bit, or (v, negated) meaning (v != 0) ^ negated
Bit = int | tuple[Expression, bool]


def _nonzero_msb_operand(expr: Expression) -> Expression | None:
    """
    For ``v | (v + (2^(n-1) - 1))`` return ``v``: the most significant bit of that is ``v != 0``. With v == 0 the sum is
    0x7f..f; a v with its top bit set sets it; any other v carries the sum into it.
    """
    if not (isinstance(expr, BinaryOp) and expr.op == "Or") or expr.floating_point:
        return None
    k = (1 << (expr.bits - 1)) - 1
    for v, s in (expr.operands, expr.operands[::-1]):
        if not (isinstance(s, BinaryOp) and s.op == "Add" and s.bits == expr.bits and v.bits == expr.bits):
            continue
        for a, c in (s.operands, s.operands[::-1]):
            if isinstance(c, Const) and isinstance(c.value, int) and c.value_int == k and same_value(a, v):
                return v
    return None


def bit_of(expr: Expression, j: int, depth: int = 0) -> Bit | None:
    """Bit ``j`` of ``expr`` as a constant or a zero test, through bitwise operations, shifts and concatenations."""
    if depth > _MAX_DEPTH or not 0 <= j < expr.bits:
        return None
    if isinstance(expr, Const):
        return (expr.value_int >> j) & 1 if isinstance(expr.value, int) else None
    if isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg" and expr.operand.bits == expr.bits:
        b = bit_of(expr.operand, j, depth + 1)
        if b is None:
            return None
        return 1 - b if isinstance(b, int) else (b[0], not b[1])
    if isinstance(expr, Convert):
        if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
            return None
        if j < min(expr.from_bits, expr.to_bits):
            return bit_of(expr.operand, j, depth + 1)
        if expr.to_bits > expr.from_bits and not expr.is_signed:
            return 0
        return None
    if not isinstance(expr, BinaryOp) or expr.floating_point:
        return None
    op0, op1 = expr.operands
    if expr.op == "Concat":
        if j < op1.bits:
            return bit_of(op1, j, depth + 1)
        return bit_of(op0, j - op1.bits, depth + 1)
    if expr.op in {"Shr", "Shl"} and isinstance(op1, Const) and isinstance(op1.value, int) and op0.bits == expr.bits:
        src = j + op1.value_int if expr.op == "Shr" else j - op1.value_int
        if not 0 <= src < expr.bits:
            return 0
        return bit_of(op0, src, depth + 1)
    if expr.op in {"And", "Or"} and op0.bits == expr.bits and op1.bits == expr.bits:
        for c, other in ((op0, op1), (op1, op0)):
            if isinstance(c, Const) and isinstance(c.value, int):
                cb = (c.value_int >> j) & 1
                if expr.op == "And":
                    return bit_of(other, j, depth + 1) if cb else 0
                return 1 if cb else bit_of(other, j, depth + 1)
        if expr.op == "Or" and j == expr.bits - 1:
            v = _nonzero_msb_operand(expr)
            if v is not None:
                return v, False
    return None


class SingleBitZeroTest(PeepholeOptimizationExprBase):
    """
    ``(2^j & E) == 0`` / ``!= 0`` ==> a zero test, when bit ``j`` of ``E`` reduces, through bitwise operations, shifts
    and concatenations, to the most significant bit of ``v | (v + 0x7f..f)`` (which is ``v != 0``). A devirtualized VM
    computes ZF that way and branches on the bit.
    """

    __slots__ = ()

    NAME = "(2^j & E) == 0 => v == 0"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in {"CmpEQ", "CmpNE"}:
            return None
        op0, op1 = expr.operands
        if isinstance(op0, Const):
            op0, op1 = op1, op0
        if not (isinstance(op1, Const) and op1.value == 0 and isinstance(op0, BinaryOp) and op0.op == "And"):
            return None
        for c, e in (op0.operands, op0.operands[::-1]):
            if isinstance(c, Const) and isinstance(c.value, int) and e.bits == op0.bits:
                mask = c.value_int & ((1 << op0.bits) - 1)
                if mask and not mask & (mask - 1):
                    break
        else:
            return None
        bit = bit_of(e, mask.bit_length() - 1)
        if not isinstance(bit, tuple):
            return None
        v, negated = bit
        # the test is bit == 0 for CmpEQ; bit is (v != 0) ^ negated
        nonzero = (expr.op == "CmpNE") != negated
        return BinaryOp(
            expr.idx,
            "CmpNE" if nonzero else "CmpEQ",
            [v, Const(self.manager.next_atom(), 0, v.bits)],
            False,
            bits=1,
            **expr.tags,
        )
