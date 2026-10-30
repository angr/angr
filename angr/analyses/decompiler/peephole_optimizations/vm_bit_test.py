from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase
from .vm_bool_select import same_value

_MAX_DEPTH = 16

# bit j of an expression: a constant bit, or (v, negated) meaning (v != 0) ^ negated
Bit = int | tuple[Expression, bool]


def _base_and_offset(expr: Expression) -> tuple[Expression, int]:
    """``a + c`` / ``a - c`` / ``c + a`` as ``(a, c)``; anything else as ``(expr, 0)``."""
    if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"} and not expr.floating_point:
        a, c = expr.operands
        if isinstance(c, Const) and isinstance(c.value, int) and a.bits == expr.bits:
            return a, c.value_int if expr.op == "Add" else -c.value_int
        if expr.op == "Add" and isinstance(a, Const) and isinstance(a.value, int) and c.bits == expr.bits:
            return c, a.value_int
    return expr, 0


def _nonzero_msb_operand(expr: Expression) -> Expression | None:
    """
    For ``v | (v + (2^(n-1) - 1))`` return ``v``: the most significant bit of that is ``v != 0``. With v == 0 the sum is
    0x7f..f; a v with its top bit set sets it; any other v carries the sum into it. ``v`` may be ``a + c1`` and the sum
    ``a + c2`` with ``c2 - c1 == 2^(n-1) - 1`` (mod 2^n), the shape left once constants are folded.
    """
    if not (isinstance(expr, BinaryOp) and expr.op == "Or") or expr.floating_point:
        return None
    mask = (1 << expr.bits) - 1
    k = (1 << (expr.bits - 1)) - 1
    for v, s in (expr.operands, expr.operands[::-1]):
        if v.bits != expr.bits or s.bits != expr.bits:
            continue
        for v_base, v_off in ((v, 0), _base_and_offset(v)):
            for s_base, s_off in ((s, 0), _base_and_offset(s)):
                if (s_off - v_off) & mask == k and same_value(v_base, s_base):
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
