from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase
from .bool_scaled_mask import _int_const, _log2
from .known_bits import block_defs_resolver, known_bits


class ScaledCmpZero(PeepholeOptimizationExprBase):
    """
    ``(b * 2**k) == 0`` ==> ``b == 0`` (and ``!=``), also spelt ``b << k``, when the top ``k`` bits of ``b`` are known
    zero: the scaling then drops no set bit. A devirtualized VM tests a flag it moved into place, e.g.
    ``(~flags & 1) * 8``.
    """

    __slots__ = ()

    NAME = "(b * 2**k) cmp 0 => b cmp 0"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, block_defs=None, **kwargs):
        if expr.op not in {"CmpEQ", "CmpNE"} or expr.floating_point:
            return None
        op0, op1 = expr.operands
        if _int_const(op0) == 0:
            op0, op1 = op1, op0
        if _int_const(op1) != 0 or not isinstance(op0, BinaryOp) or op0.floating_point:
            return None
        bits = op0.bits
        b = None
        k = None
        if op0.op == "Mul":
            for base, factor in (op0.operands, op0.operands[::-1]):
                j = _log2(_int_const(factor))
                if j is not None and base.bits == bits and not isinstance(base, Const):
                    b, k = base, j
                    break
        elif op0.op == "Shl" and op0.operands[0].bits == bits:
            b, k = op0.operands[0], _int_const(op0.operands[1])
        if b is None or k is None or not 0 < k < bits:
            return None
        zeros, _ = known_bits(
            b, block_defs_resolver(block_defs), tmps=block_defs.tmps if block_defs is not None else None
        )
        high = ((1 << k) - 1) << (bits - k)
        if zeros & high != high:
            return None
        return BinaryOp(
            expr.idx, expr.op, [b, Const(self.manager.next_atom(), 0, bits)], False, bits=expr.bits, **expr.tags
        )
