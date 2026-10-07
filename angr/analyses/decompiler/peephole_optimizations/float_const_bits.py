from __future__ import annotations

import struct

from angr.ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase

_BITWISE_OPS = frozenset({"And", "Or", "Xor", "Shl", "Shr", "Sar"})


def _float_const_bits(const: Const) -> int | None:
    """The bit pattern of a floating-point constant, or None if the constant is not one."""
    if not isinstance(const.value, float):
        return None
    if const.bits == 32:
        return struct.unpack("<I", struct.pack("<f", const.value))[0]
    if const.bits == 64:
        return struct.unpack("<Q", struct.pack("<d", const.value))[0]
    return None


class FloatConstBits(PeepholeOptimizationExprBase):
    """
    A floating-point constant under a bitwise operation or an integer widening is its bit pattern: a sign mask
    loaded into an FP register (``movsd xmm1, [-0.0]; xorpd xmm0, xmm1``) is ``0x8000000000000000``, not ``-0.0``.
    """

    __slots__ = ()

    NAME = "Replace floating-point constants under bitwise operations with their bit patterns"
    expr_classes = (BinaryOp, Convert)

    def optimize(self, expr: BinaryOp | Convert, **kwargs):
        if isinstance(expr, Convert):
            if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
                return None
            operand = expr.operand
            if not isinstance(operand, Const):
                return None
            bits = _float_const_bits(operand)
            if bits is None:
                return None
            return Convert(
                expr.idx,
                expr.from_bits,
                expr.to_bits,
                expr.is_signed,
                Const(operand.idx, bits, operand.bits, **operand.tags),
                from_type=expr.from_type,
                to_type=expr.to_type,
                rounding_mode=expr.rounding_mode,
                vector_count=expr.vector_count,
                **expr.tags,
            )

        if expr.op not in _BITWISE_OPS:
            return None
        operands = list(expr.operands)
        changed = False
        for i, operand in enumerate(operands):
            if isinstance(operand, Const):
                bits = _float_const_bits(operand)
                if bits is not None:
                    operands[i] = Const(operand.idx, bits, operand.bits, **operand.tags)
                    changed = True
        if not changed:
            return None
        return BinaryOp(
            expr.idx,
            expr.op,
            operands,
            expr.signed,
            bits=expr.bits,
            floating_point=expr.floating_point,
            rounding_mode=expr.rounding_mode,
            vector_count=expr.vector_count,
            vector_size=expr.vector_size,
            **expr.tags,
        )
