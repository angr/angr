from __future__ import annotations
import struct

from ailment.expression import Reinterpret, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantReinterprets(PeepholeOptimizationExprBase):
    """
    Simplify nested and constant Reinterpret() expressions.
    """

    __slots__ = ()

    NAME = "Simplifying nested and constant Reinterprets"
    expr_classes = (Reinterpret,)  # all expressions are allowed

    def optimize(self, expr: Reinterpret, **kwargs):
        if isinstance(expr.operand, Reinterpret):
            inner = expr.operand
            if expr.from_type == inner.to_type and expr.to_type == inner.from_type:
                return inner.operand

        if expr.from_type == "I" and expr.to_type == "F" and isinstance(expr.operand, Const):
            # replace it with a floating point constant
            if expr.operand.bits == 32:
                int_fmt = "<I"
            elif expr.operand.bits == 64:
                int_fmt = "<Q"
            else:
                raise NotImplementedError

            if expr.bits == 32:
                float_fmt = "<f"
            elif expr.bits == 64:
                float_fmt = "<d"
            else:
                raise NotImplementedError

            value = struct.unpack(float_fmt, struct.pack(int_fmt, expr.operand.value))[0]
            return Const(expr.idx, None, value, expr.bits, **expr.tags)

        return None
