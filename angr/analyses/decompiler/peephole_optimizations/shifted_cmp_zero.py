from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase
from .bool_scaled_mask import _int_const
from .known_bits import block_defs_resolver, known_bits

_UNSIGNED_OK = {"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"}


class ShiftedCmpZero(PeepholeOptimizationExprBase):
    """
    ``(x >> k) cmp 0`` ==> ``x cmp 0`` when the ``k`` bits shifted out of ``x`` are known zero: the shift then keeps
    whether ``x`` is zero (and, for ``>>`` arithmetic, its sign). The unsigned bound form ``x <= 2**k - 1`` /
    ``x > 2**k - 1`` (how ``(x >> k) == 0`` is often spelt) becomes ``x == 0`` / ``x != 0`` likewise. E.g. a VM's
    ``(flags & 64) >> 3 == 0``, printed ``(flags & 64) <= 7``, is ``(flags & 64) == 0``.
    """

    __slots__ = ()

    NAME = "(x >> k) cmp 0 => x cmp 0 for known-zero low bits"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, block_defs=None, **kwargs):
        if expr.op not in _UNSIGNED_OK or expr.floating_point:
            return None
        op0, op1 = expr.operands
        c = _int_const(op1)
        if c is None or isinstance(op0, Const):
            return None
        op = expr.op
        if c == 0 and isinstance(op0, BinaryOp) and op0.op in {"Shr", "Sar"} and op0.operands[0].bits == op0.bits:
            k = _int_const(op0.operands[1])
            if k is None or not 0 < k < op0.bits:
                return None
            if expr.signed and op0.op == "Shr":
                # a logical shift clears the sign bit
                return None
            x = op0.operands[0]
        elif not expr.signed and op in {"CmpLE", "CmpGT"} and c > 0 and (c + 1) & c == 0:
            # x <=u 2**k - 1
            k = c.bit_length()
            if k >= op0.bits:
                return None
            x = op0
            op = "CmpEQ" if op == "CmpLE" else "CmpNE"
        else:
            return None
        zeros, _ = known_bits(
            x, block_defs_resolver(block_defs), tmps=block_defs.tmps if block_defs is not None else None
        )
        low = (1 << k) - 1
        if zeros & low != low:
            return None
        return BinaryOp(
            expr.idx,
            op,
            [x, Const(self.manager.next_atom(), 0, x.bits)],
            expr.signed,
            bits=expr.bits,
            **expr.tags,
        )
