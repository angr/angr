from __future__ import annotations

import struct

from angr.ailment.expression import BinaryOp, Const, Convert, Load, Reinterpret, UnaryOp

from .base import PeepholeOptimizationExprBase


class RemoveRedundantReinterprets(PeepholeOptimizationExprBase):
    """
    Simplify Reinterpret() expressions: nested and constant ones, the integer view VEX puts between a floating-point
    register and memory (``Reinterpret(I->F, Load)``: memory is untyped, the load carries the float), and a view
    whose consumer expects the original type (an integer operation on ``Reinterpret(I->F, x)`` operates on ``x``).
    """

    __slots__ = ()

    NAME = "Simplifying nested, constant, and type-consistent Reinterprets"
    expr_classes = (Reinterpret, BinaryOp, UnaryOp, Convert)

    def optimize(self, expr: Reinterpret | BinaryOp | UnaryOp | Convert, **kwargs):
        if isinstance(expr, Reinterpret):
            return self._optimize_Reinterpret(expr)
        if isinstance(expr, Convert):
            return self._optimize_Convert(expr)
        return self._optimize_Op(expr)

    def _optimize_Reinterpret(self, expr: Reinterpret):
        operand = expr.operand
        if isinstance(operand, Reinterpret) and expr.from_type == operand.to_type and expr.to_type == operand.from_type:
            return operand.operand

        if isinstance(operand, (BinaryOp, UnaryOp)) and operand.floating_point == (expr.from_type == "I"):
            # viewing an integer-valued operation as an integer (or a floating-point one as a float) is a no-op
            return operand

        if expr.from_type == "I" and expr.to_type == "F":
            if isinstance(operand, Load) and operand.bits == expr.bits:
                return operand
            if isinstance(operand, Const) and isinstance(operand.value, int):
                # replace it with a floating point constant
                int_fmt, float_fmt = self._formats(operand.bits, expr.bits)
                value = struct.unpack(float_fmt, struct.pack(int_fmt, operand.value))[0]
                return Const(expr.idx, value, expr.bits, **expr.tags)

        if (
            expr.from_type == "F"
            and expr.to_type == "I"
            and isinstance(operand, Const)
            and isinstance(operand.value, float)
        ):
            # replace it with the bit pattern of the floating point constant
            int_fmt, float_fmt = self._formats(expr.bits, operand.bits)
            value = struct.unpack(int_fmt, struct.pack(float_fmt, operand.value))[0]
            return Const(expr.idx, value, expr.bits, **expr.tags)

        return None

    @staticmethod
    def _consistent(operand, consumer_is_fp: bool):
        """Strip a Reinterpret whose source type is what the consumer operates on."""
        if isinstance(operand, Reinterpret) and (operand.from_type == "F") == consumer_is_fp:
            return operand.operand
        return None

    def _optimize_Op(self, expr: BinaryOp | UnaryOp):
        if expr.vector_count is not None if isinstance(expr, BinaryOp) else False:
            return None
        operands = list(expr.operands)
        changed = False
        for i, operand in enumerate(operands):
            stripped = self._consistent(operand, expr.floating_point)
            if stripped is not None:
                operands[i] = stripped
                changed = True
        if not changed:
            return None
        if isinstance(expr, UnaryOp):
            return UnaryOp(
                expr.idx, expr.op, operands[0], bits=expr.bits, floating_point=expr.floating_point, **expr.tags
            )
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

    def _optimize_Convert(self, expr: Convert):
        if expr.vector_count is not None or expr.to_bits >= 128:
            # a zero-extension into a vector register places the lane; it does not operate on the integer
            return None
        stripped = self._consistent(expr.operand, expr.from_type == Convert.TYPE_FP)
        if stripped is None:
            return None
        return Convert(
            expr.idx,
            expr.from_bits,
            expr.to_bits,
            expr.is_signed,
            stripped,
            from_type=expr.from_type,
            to_type=expr.to_type,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )

    @staticmethod
    def _formats(int_bits: int, float_bits: int) -> tuple[str, str]:
        if int_bits == 32:
            int_fmt = "<I"
        elif int_bits == 64:
            int_fmt = "<Q"
        else:
            raise NotImplementedError

        if float_bits == 32:
            float_fmt = "<f"
        elif float_bits == 64:
            float_fmt = "<d"
        else:
            raise NotImplementedError
        return int_fmt, float_fmt
