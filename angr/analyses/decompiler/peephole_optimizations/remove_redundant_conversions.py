# pylint: disable=missing-class-docstring,too-many-boolean-expressions
from __future__ import annotations
from angr.ailment.expression import BinaryOp, Convert, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove or rewrite redundant conversions around binary operators"
    expr_classes = (BinaryOp, Convert)

    def optimize(self, expr: BinaryOp | Convert, **kwargs):

        if isinstance(expr, BinaryOp):
            return self._optimize_BinaryOp(expr)
        if isinstance(expr, Convert):
            return self._optimize_Convert(expr)
        return None

    @staticmethod
    def _optimize_BinaryOp(expr: BinaryOp):
        # TODO make this lhs/rhs agnostic
        if isinstance(expr.operands[0], Convert):  # noqa: SIM102
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

        # simpler cases
        # (A & mask) & mask  ==>  A & mask
        if (
            expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and isinstance(expr.operands[0], BinaryOp)
            and expr.operands[0].op == "And"
        ):
            inner_op0, inner_op1 = expr.operands[0].operands
            if (isinstance(inner_op0, Const) and inner_op0.value == expr.operands[1].value) or (
                isinstance(inner_op1, Const) and inner_op1.value == expr.operands[1].value
            ):
                return expr.operands[0]

        return None

    @staticmethod
    def _optimize_Convert(expr: Convert):
        operand_expr = expr.operand
        if isinstance(operand_expr, BinaryOp):
            if operand_expr.op in {
                "Mul",
                "Shl",
                "Div",
                "DivMod",
                "Mod",
                "Add",
                "Sub",
            }:
                op0, op1 = operand_expr.operands
                if (
                    isinstance(op0, Convert)
                    and isinstance(op1, Convert)
                    and op0.from_bits == op1.from_bits
                    and op0.to_bits == op1.to_bits
                    and expr.from_bits == op0.to_bits
                    and expr.to_bits == op1.from_bits
                ):
                    return BinaryOp(
                        operand_expr.idx,
                        operand_expr.op,
                        [op0.operand, op1.operand],
                        expr.is_signed,
                        **operand_expr.tags,
                    )
            elif operand_expr.op == "Or" and expr.from_bits > expr.to_bits:
                # Conv(64->32,((vvar_183{reg 128} & 0xffffffff00000000<64>)
                #   | Conv(32->64, Load(addr=0x200002dc<32>, size=4, endness=Iend_LE))))
                # =>
                # Conv(64->32, Load(addr=0x200002dc<32>, size=4, endness=Iend_LE))
                high_mask = ((1 << expr.from_bits) - 1) - ((1 << expr.to_bits) - 1)
                op0, op1 = operand_expr.operands
                if (
                    isinstance(op0, BinaryOp)
                    and op0.op == "And"
                    and isinstance(op0.operands[1], Const)
                    and op0.operands[1].value == high_mask
                ):
                    return Convert(
                        expr.idx,
                        expr.from_bits,
                        expr.to_bits,
                        expr.is_signed,
                        op1,
                        **expr.tags,
                    )
                if (
                    isinstance(op1, BinaryOp)
                    and op1.op == "And"
                    and isinstance(op1.operands[1], Const)
                    and op1.operands[1].value == high_mask
                ):
                    return Convert(
                        expr.idx,
                        expr.from_bits,
                        expr.to_bits,
                        expr.is_signed,
                        op0,
                        **expr.tags,
                    )

            if (
                expr.to_bits < expr.from_bits
                and expr.from_type == Convert.TYPE_INT
                and expr.to_type == Convert.TYPE_INT
            ):
                if operand_expr.op in {"Add", "And", "Xor", "Or", "Mul"}:
                    # ignore the high bits of each operand
                    op0, op1 = operand_expr.operands
                    new_op0 = Convert(
                        expr.idx,
                        expr.from_bits,
                        expr.to_bits,
                        False,
                        op0,
                        **expr.tags,
                    )
                    new_op1 = Convert(
                        expr.idx,
                        expr.from_bits,
                        expr.to_bits,
                        False,
                        op1,
                        **expr.tags,
                    )

                    return BinaryOp(
                        expr.idx,
                        operand_expr.op,
                        [new_op0, new_op1],
                        operand_expr.signed,
                        bits=expr.to_bits,
                        **operand_expr.tags,
                    )
                if operand_expr.op in {"Shr", "Sar"} and isinstance(operand_expr.operands[0], Convert):
                    op0, op1 = operand_expr.operands
                    assert isinstance(op0, Convert)
                    if op0.to_bits > op0.from_bits and op0.to_bits == expr.from_bits:
                        new_operand = BinaryOp(
                            expr.idx,
                            operand_expr.op,
                            [op0.operand, op1],
                            operand_expr.signed,
                            bits=op0.from_bits,
                            **operand_expr.tags,
                        )
                        return Convert(
                            expr.idx,
                            new_operand.bits,
                            expr.to_bits,
                            expr.is_signed,
                            new_operand,
                            **expr.tags,
                        )
        return None
