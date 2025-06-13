# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class ModuloSimplifier(PeepholeOptimizationExprBase):
    """
    Simplify division and multiplication expressions that can be reduced to a modulo operation.
    """

    __slots__ = ()

    NAME = "a - (a / N) * N => a % N"
    expr_classes = (BinaryOp,)

    def optimize(  # pylint:disable=unused-argument
        self, expr: BinaryOp, stmt_idx: int | None = None, block=None, **kwargs
    ):
        if expr.op == "Sub" and len(expr.operands) == 2:
            sub0, sub1 = expr.operands
            # unpack Conversions
            outer_conv_expr = None
            if (
                isinstance(sub0, Convert)
                and isinstance(sub1, Convert)
                and sub0.to_bits == sub1.to_bits
                and sub0.from_bits == sub1.from_bits
                and sub0.to_bits > sub0.from_bits
                and sub0.is_signed == sub1.is_signed
            ):
                # Convert(a) - Convert(a / N * N)  ==> Convert(a % N)
                outer_conv_expr = sub0
                sub0 = sub0.operand
                sub1 = sub1.operand

            if isinstance(sub1, BinaryOp) and sub1.op == "Mul" and isinstance(sub1.operands[1], Const):
                a0, op1 = sub0, sub1
                op1_left = op1.operands[0]
                mul_const = sub1.operands[1]

                if (
                    isinstance(op1_left, Convert)
                    and isinstance(a0, Convert)
                    and op1_left.to_bits == a0.to_bits
                    and op1_left.from_bits == a0.from_bits
                ):
                    # Convert(a) - (Convert(a / N)) * N  ==>  Convert(a) % N
                    inner_conv_expr = a0
                    a0 = a0.operand
                    op1_left = op1_left.operand
                else:
                    inner_conv_expr = None

                if isinstance(op1_left, BinaryOp) and op1_left.op == "Div" and isinstance(op1_left.operands[1], Const):
                    # a - (a / N) * N  ==>  a % N
                    a1 = op1_left.operands[0]
                    div_const = op1_left.operands[1]

                    if a0.likes(a1) and mul_const.value == div_const.value:
                        operands = [a0, div_const]
                        mod = BinaryOp(expr.idx, "Mod", operands, False, bits=a0.bits, **expr.tags)
                        if inner_conv_expr is not None:
                            conv_from_bits = inner_conv_expr.from_bits
                            conv_to_bits = (
                                inner_conv_expr.to_bits if outer_conv_expr is None else outer_conv_expr.to_bits
                            )
                            conv_signed = inner_conv_expr.is_signed
                            conv_expr = inner_conv_expr
                        elif outer_conv_expr is not None:
                            conv_from_bits = outer_conv_expr.from_bits
                            conv_to_bits = outer_conv_expr.to_bits
                            conv_signed = outer_conv_expr.is_signed
                            conv_expr = outer_conv_expr
                        else:
                            # no conversion necessary
                            return mod

                        return Convert(
                            conv_expr.idx,
                            conv_from_bits,
                            conv_to_bits,
                            conv_signed,
                            mod,
                            **conv_expr.tags,
                        )

        return None
