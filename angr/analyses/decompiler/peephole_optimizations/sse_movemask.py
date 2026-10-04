"""SSE/AVX sign-mask extraction (movmskpd / movmskps / vmovmskpd / vmovmskps).

VEX lifts ``movmskpd eax, xmm0`` lane by lane: the sign bit of lane i is shifted into bit i of the result::

    ((Extract(v, 32@4) >> 31) & 1) | ((Extract(v, 32@12) >> 30) & 2)

The whole Or-tree becomes ``MovMskPD(v)`` / ``MovMskPS(v)`` (rendered as ``_mm_movemask_pd(v)``, or ``signbit(v)``
when v is a scalar). When the consumer masks the result down to bit 0, the upper-lane terms drop out and the read
becomes ``SignBit(lane0(v))``.
"""

from __future__ import annotations

from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Expression,
    Extract,
    Reinterpret,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)

from .base import PeepholeOptimizationExprBase
from .sse_vector_lane_lowering import lane0

# lane width in bytes -> op name
MOVEMASK_OPS: dict[int, str] = {8: "MovMskPD", 4: "MovMskPS"}
_LANE_BYTES: dict[str, int] = {v: k for k, v in MOVEMASK_OPS.items()}


def _flatten_or(expr: Expression, out: list[Expression]) -> None:
    if isinstance(expr, BinaryOp) and expr.op == "Or":
        _flatten_or(expr.operands[0], out)
        _flatten_or(expr.operands[1], out)
    else:
        out.append(expr)


def _match_lane_bit(expr: Expression) -> tuple[int, Expression, int] | None:
    """Match ``(Extract(base, 32@off) >> (31 - i)) & (1 << i)`` and return (i, base, off). For i = 0 the mask may
    already have been dropped, and a 32-bit base may be read directly (off = 0)."""
    if isinstance(expr, BinaryOp) and expr.op == "And" and isinstance(expr.operands[1], Const):
        mask = expr.operands[1].value
        shr = expr.operands[0]
    else:
        mask = 1
        shr = expr
    if not (
        isinstance(mask, int)
        and mask > 0
        and mask & (mask - 1) == 0
        and isinstance(shr, BinaryOp)
        and shr.op == "Shr"
        and isinstance(shr.operands[1], Const)
    ):
        return None
    i = mask.bit_length() - 1
    if shr.operands[1].value != 31 - i or (shr is expr and i != 0):
        return None
    word = shr.operands[0]
    if isinstance(word, Reinterpret) and word.from_type == "F" and word.to_type == "I":
        word = word.operand
    if isinstance(word, Extract) and word.bits == 32 and word.endness == "Iend_LE" and isinstance(word.offset, Const):
        off = word.offset.value
        assert isinstance(off, int)
        return i, word.base, off
    if isinstance(word, VirtualVariable) and word.bits == 32:
        return i, word, 0
    return None


def _is_vector_reg_vvar(expr: Expression, arch) -> bool:
    if not isinstance(expr, VirtualVariable):
        return False
    if expr.was_reg:
        offset = expr.reg_offset
    elif expr.was_parameter and expr.parameter_category == VirtualVariableCategory.REGISTER:
        offset = expr.parameter_reg_offset
    else:
        return False
    return any(r.vector and r.vex_offset <= offset < r.vex_offset + r.size for r in arch.register_list)


def _known_bits(expr: Expression) -> int | None:
    """A mask covering every bit of *expr* that may be set, if cheaply known."""
    if isinstance(expr, BinaryOp) and expr.op == "And" and isinstance(expr.operands[1], Const):
        v = expr.operands[1].value
        return v if isinstance(v, int) else None
    return None


class SSEMoveMask(PeepholeOptimizationExprBase):
    """Fold the lane-wise sign-bit gathering of movmskpd/movmskps into one op, and reduce bit-0 reads to signbit."""

    __slots__ = ()

    NAME = "SSE movmskpd/movmskps to MovMsk/SignBit"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op == "Or":
            return self._fold_movemask(expr)
        if expr.op == "And" and isinstance(expr.operands[1], Const) and expr.operands[1].value == 1:
            return self._lane0_sign(expr)
        return None

    def _fold_movemask(self, expr: BinaryOp) -> UnaryOp | None:
        terms: list[Expression] = []
        _flatten_or(expr, terms)
        if len(terms) not in (2, 4, 8):
            return None
        lanes: dict[int, tuple[Expression, int]] = {}
        for term in terms:
            m = _match_lane_bit(term)
            if m is None or m[0] in lanes:
                return None
            lanes[m[0]] = m[1], m[2]
        n = len(terms)
        if set(lanes) != set(range(n)):
            return None
        base = lanes[0][0]
        if base.bits not in (128, 256):
            return None
        lane_bytes = base.bits // 8 // n
        if lane_bytes not in MOVEMASK_OPS:
            return None
        for i, (b, off) in lanes.items():
            # the 32-bit word holding the lane's sign bit
            if off != (i + 1) * lane_bytes - 4 or not b.likes(base):
                return None
        return UnaryOp(expr.idx, MOVEMASK_OPS[lane_bytes], base, bits=expr.bits, **expr.tags)

    def _sign_bit(self, expr: BinaryOp, vec: Expression, lane_bytes: int) -> Convert:
        lane = lane0(vec, lane_bytes * 8, self.manager)
        sign = UnaryOp(self.manager.next_atom(), "SignBit", lane, bits=1, floating_point=True, **expr.tags)
        return Convert(expr.idx, 1, expr.bits, False, sign, **expr.tags)

    def _lane0_sign(self, expr: BinaryOp) -> Expression | None:
        inner = expr.operands[0]
        if isinstance(inner, UnaryOp) and inner.op in _LANE_BYTES:
            return self._sign_bit(expr, inner.operand, _LANE_BYTES[inner.op])
        if (
            isinstance(inner, BinaryOp)
            and inner.op == "Shr"
            and isinstance(inner.operands[1], Const)
            and isinstance(word := inner.operands[0], Reinterpret)
            and word.from_type == "F"
            and word.to_type == "I"
            and isinstance(word.operand, VirtualVariable)
            and inner.operands[1].value == word.to_bits - 1
        ):
            # the top bit of a float's bit pattern (movmskps on a scalar float)
            return self._sign_bit(expr, word.operand, word.from_bits // 8)
        if not (isinstance(inner, BinaryOp) and inner.op == "Or"):
            return None

        # (lane0 | upper lanes) & 1: terms whose bits are all above bit 0 drop out
        terms: list[Expression] = []
        _flatten_or(inner, terms)
        kept = [t for t in terms if (k := _known_bits(t)) is None or k & 1]
        if len(kept) != 1 or len(kept) == len(terms):
            return None
        term = kept[0]
        m = _match_lane_bit(term)
        if m is not None and m[0] == 0 and self.project is not None and _is_vector_reg_vvar(m[1], self.project.arch):
            lane_bytes = m[2] + 4
            if lane_bytes in MOVEMASK_OPS and m[1].bits >= lane_bytes * 8:
                return self._sign_bit(expr, m[1], lane_bytes)
        return BinaryOp(expr.idx, "And", [term, expr.operands[1]], expr.signed, bits=expr.bits, **expr.tags)
