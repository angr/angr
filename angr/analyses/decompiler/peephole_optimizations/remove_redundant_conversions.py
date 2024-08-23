# pylint: disable=missing-class-docstring
from __future__ import annotations
from ailment.expression import BinaryOp, Convert, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant conversions around binary operators"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        # TODO make this lhs/rhs agnostic
        if isinstance(expr.operands[0], Convert):
            # check: is the lhs convert an up-cast and is rhs a const?
            if expr.operands[0].to_bits > expr.operands[0].from_bits and isinstance(expr.operands[1], Const):
                to_bits = expr.operands[0].to_bits
                from_bits = expr.operands[0].from_bits
                if expr.op == "And":
                    if 0 <= expr.operands[1].value <= ((1 << from_bits) - 1) or expr.operands[1].value >= (
                        1 << to_bits
                    ) - (1 << (from_bits - 1)):
                        con = Const(None, None, expr.operands[1].value, from_bits, **expr.operands[1].tags)
                        new_expr = BinaryOp(
                            expr.idx, "And", (expr.operands[0].operand, con), expr.signed, bits=from_bits, **expr.tags
                        )
                        return Convert(
                            expr.operands[0].idx,
                            from_bits,
                            to_bits,
                            expr.operands[0].is_signed,
                            new_expr,
                            **expr.operands[0].tags,
                        )

                elif expr.op in {
                    "CmpEQ",
                    "CmpNE",
                    "CmpGT",
                    "CmpGE",
                    "CmpGTs",
                    "CmpGEs",
                    "CmpLT",
                    "CmpLE",
                    "CmpLTs",
                    "CmpLEs",
                }:
                    if 0 <= expr.operands[1].value <= ((1 << from_bits) - 1) or (
                        expr.operands[0].is_signed and expr.operands[1].value >= (1 << to_bits) - (1 << (from_bits - 1))
                    ):
                        con = Const(None, None, expr.operands[1].value, from_bits, **expr.operands[1].tags)
                        return BinaryOp(
                            expr.idx, expr.op, (expr.operands[0].operand, con), expr.signed, bits=1, **expr.tags
                        )

                elif expr.op in {"Add", "Sub"}:
                    # Add(Conv(32->64, expr), A) ==> Conv(32->64, Add(expr, A))
                    op0, op1 = expr.operands
                    con = Const(op1.idx, op1.variable, op1.value, op0.from_bits)
                    return Convert(
                        op0.idx,
                        op0.from_bits,
                        op0.to_bits,
                        op0.is_signed,
                        BinaryOp(
                            expr.idx, expr.op, [op0.operand, con], expr.signed, bits=op0.operand.bits, **expr.tags
                        ),
                        **op0.tags,
                    )

            elif (
                isinstance(expr.operands[1], Convert)
                and expr.operands[1].to_bits == expr.operands[0].to_bits
                and expr.operands[1].from_bits == expr.operands[0].from_bits
            ):
                if expr.op in {"Add", "Sub"}:
                    op0 = expr.operands[0]
                    op0_inner = expr.operands[0].operand
                    # op1 = expr.operands[1]
                    op1_inner = expr.operands[1].operand

                    new_expr = BinaryOp(
                        expr.idx,
                        expr.op,
                        (op0_inner, op1_inner),
                        expr.signed,
                        bits=op0.from_bits,
                        **expr.tags,
                    )
                    return Convert(
                        op0.idx,
                        op0.from_bits,
                        op0.to_bits,
                        op0.is_signed,
                        new_expr,
                        **op0.tags,
                    )

        # a more complex case
        # (Conv(expr) >> A) & B == C  ==>  (expr >> A) & B == C
        if expr.op in {
            "CmpEQ",
            "CmpNE",
            "CmpGT",
            "CmpGE",
            "CmpGTs",
            "CmpGEs",
            "CmpLT",
            "CmpLE",
            "CmpLTs",
            "CmpLEs",
        } and isinstance(expr.operands[1], Const):
            op0 = expr.operands[0]
            if isinstance(op0, BinaryOp):
                left, b = op0.operands
                if (
                    isinstance(b, Const)
                    and isinstance(left, BinaryOp)
                    and left.op
                    in {
                        "Shr",
                        "Sar",
                        "Shl",
                    }
                ):
                    shift_lhs, a = left.operands
                    if isinstance(a, Const) and isinstance(shift_lhs, Convert):
                        from_bits = shift_lhs.from_bits
                        if 0 < a.value < from_bits:
                            c = expr.operands[1]
                            r0 = BinaryOp(
                                left.idx,
                                left.op,
                                [shift_lhs.operand, Const(a.idx, a.variable, a.value, from_bits)],
                                left.signed,
                                bits=from_bits,
                                **left.tags,
                            )
                            r1 = BinaryOp(
                                op0.idx,
                                op0.op,
                                [r0, Const(b.idx, b.variable, b.value, from_bits)],
                                op0.signed,
                                bits=from_bits,
                                **op0.tags,
                            )
                            return BinaryOp(
                                expr.idx,
                                expr.op,
                                [r1, Const(c.idx, c.variable, c.value, from_bits)],
                                expr.signed,
                                bits=from_bits,
                                **expr.tags,
                            )

        return None
