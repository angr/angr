from __future__ import annotations
from math import gcd

from angr.ailment.expression import BinaryOp, UnaryOp, Const, Convert, StackBaseOffset

from angr.utils.bits import sign_extend
from .base import PeepholeOptimizationExprBase


class EagerEvaluation(PeepholeOptimizationExprBase):
    """
    Eagerly evaluates certain types of expressions.
    """

    __slots__ = ()

    NAME = "Eager expression evaluation"
    expr_classes = (BinaryOp, UnaryOp, Convert)

    def optimize(self, expr, **kwargs):  # type:ignore
        if isinstance(expr, BinaryOp):
            return self._optimize_binaryop(expr)
        if isinstance(expr, Convert):
            return self._optimize_convert(expr)
        if isinstance(expr, UnaryOp):
            return self._optimize_unaryop(expr)
        return None

    @staticmethod
    def _optimize_binaryop(expr: BinaryOp):
        if expr.op == "Add":
            if (
                isinstance(expr.operands[0], Const)
                and isinstance(expr.operands[0].value, int)
                and isinstance(expr.operands[1], Const)
                and isinstance(expr.operands[1].value, int)
            ):
                mask = (1 << expr.bits) - 1
                return Const(
                    expr.idx, None, (expr.operands[0].value + expr.operands[1].value) & mask, expr.bits, **expr.tags
                )
            if isinstance(expr.operands[1], Const) and expr.operands[1].value == 0:
                return expr.operands[0]
            if (
                isinstance(expr.operands[1], Const)
                and isinstance(expr.operands[0], BinaryOp)
                and isinstance(expr.operands[0].operands[1], Const)
            ):
                left = expr.operands[0]
                inner_expr, const_0 = left.operands
                const_1 = expr.operands[1]
                if left.op == "Add":
                    return BinaryOp(
                        left.idx,
                        "Add",
                        [inner_expr, Const(const_0.idx, None, const_0.value + const_1.value, const_0.bits)],
                        expr.signed,
                        **expr.tags,
                    )
                if left.op == "Sub":
                    return BinaryOp(
                        left.idx,
                        "Add",
                        [inner_expr, Const(const_0.idx, None, const_1.value - const_0.value, const_0.bits)],
                        expr.signed,
                        **expr.tags,
                    )
            op0, op1 = expr.operands
            if op0.likes(op1):
                # x + x => 2 * x
                count = Const(expr.idx, None, 2, op0.bits, **expr.tags)
                return BinaryOp(expr.idx, "Mul", [op0, count], expr.signed, **expr.tags)

            op0_is_mulconst = (
                isinstance(op0, BinaryOp)
                and op0.op == "Mul"
                and (isinstance(op0.operands[0], Const) or isinstance(op0.operands[1], Const))
            )
            op1_is_mulconst = (
                isinstance(op1, BinaryOp)
                and op1.op == "Mul"
                and (isinstance(op1.operands[0], Const) or isinstance(op1.operands[1], Const))
            )
            const0, x0 = None, None
            const1, x1 = None, None
            if op0_is_mulconst:
                if isinstance(op0.operands[0], Const):
                    const0, x0 = op0.operands
                elif isinstance(op0.operands[1], Const):
                    x0, const0 = op0.operands
            if op1_is_mulconst:
                if isinstance(op1.operands[0], Const):
                    const1, x1 = op1.operands
                elif isinstance(op1.operands[1], Const):
                    x1, const1 = op1.operands

            if op0_is_mulconst ^ op1_is_mulconst:
                if x0 is not None and const0 is not None and x0.likes(op1):
                    # x * A + x => (A + 1) * x
                    new_const = Const(const0.idx, None, const0.value + 1, const0.bits, **const0.tags)
                    return BinaryOp(expr.idx, "Mul", [x0, new_const], expr.signed, **expr.tags)
                if x1 is not None and const1 is not None and x1.likes(op0):
                    # x + x * A => (A + 1) * x
                    new_const = Const(const1.idx, None, const1.value + 1, const1.bits, **const1.tags)
                    return BinaryOp(expr.idx, "Mul", [x1, new_const], expr.signed, **expr.tags)
            elif op0_is_mulconst and op1_is_mulconst:
                assert x0 is not None and x1 is not None and const0 is not None and const1 is not None
                if x0.likes(x1):
                    # x * A + x * B => (A + B) * x
                    new_const = Const(const0.idx, None, const0.value + const1.value, const0.bits, **const0.tags)
                    return BinaryOp(expr.idx, "Mul", [x0, new_const], expr.signed, **expr.tags)

        elif expr.op == "Sub":
            if (
                isinstance(expr.operands[0], Const)
                and isinstance(expr.operands[0].value, int)
                and isinstance(expr.operands[1], Const)
                and isinstance(expr.operands[1].value, int)
            ):
                mask = (1 << expr.bits) - 1
                return Const(
                    expr.idx, None, (expr.operands[0].value - expr.operands[1].value) & mask, expr.bits, **expr.tags
                )
            if isinstance(expr.operands[1], Const) and expr.operands[1].is_int and expr.operands[1].sign_bit == 1:
                # x - (-A)  ==>  x + A
                assert isinstance(expr.operands[1].value, int)
                mask = (1 << expr.operands[1].bits) - 1
                complement = Const(
                    expr.operands[1].idx,
                    expr.operands[1].variable,
                    ((~expr.operands[1].value) + 1) & mask,
                    expr.operands[1].bits,
                    **expr.operands[1].tags,
                )
                return BinaryOp(
                    expr.idx,
                    "Add",
                    [expr.operands[0], complement],
                    expr.signed,
                    variable=expr.variable,
                    variable_offset=expr.variable_offset,
                    bits=expr.bits,
                    **expr.tags,
                )

            if (
                isinstance(expr.operands[1], Const)
                and isinstance(expr.operands[0], BinaryOp)
                and isinstance(expr.operands[0].operands[1], Const)
            ):
                left = expr.operands[0]
                inner_expr, const_0 = left.operands
                const_1 = expr.operands[1]
                if left.op == "Add":
                    return BinaryOp(
                        left.idx,
                        "Sub",
                        [inner_expr, Const(const_0.idx, None, const_1.value - const_0.value, const_0.bits)],
                        expr.signed,
                        **expr.tags,
                    )
                if left.op == "Sub":
                    return BinaryOp(
                        left.idx,
                        "Sub",
                        [inner_expr, Const(const_0.idx, None, const_0.value + const_1.value, const_0.bits)],
                        expr.signed,
                        **expr.tags,
                    )
            if isinstance(expr.operands[0], Const) and expr.operands[0].value == 0:
                return UnaryOp(expr.idx, "Neg", expr.operands[1], **expr.tags)

            if isinstance(expr.operands[0], StackBaseOffset) and isinstance(expr.operands[1], StackBaseOffset):
                assert isinstance(expr.operands[0].offset, int) and isinstance(expr.operands[1].offset, int)
                return Const(expr.idx, None, expr.operands[0].offset - expr.operands[1].offset, expr.bits, **expr.tags)

        elif expr.op == "And":
            op0, op1 = expr.operands
            if (
                isinstance(op0, Const)
                and isinstance(op0.value, int)
                and isinstance(op1, Const)
                and isinstance(op1.value, int)
            ):
                return Const(expr.idx, None, (op0.value & op1.value), expr.bits, **expr.tags)
            if isinstance(op1, Const) and op1.value == 0:
                return Const(expr.idx, None, 0, expr.bits, **expr.tags)

        elif expr.op == "Mul":
            if isinstance(expr.operands[1], Const) and expr.operands[1].value == 1:
                # x * 1 => x
                return expr.operands[0]
            if (
                isinstance(expr.operands[0], Const)
                and expr.operands[0].is_int
                and isinstance(expr.operands[1], Const)
                and expr.operands[1].is_int
            ):
                assert isinstance(expr.operands[0].value, int) and isinstance(expr.operands[1].value, int)
                # constant multiplication
                mask = (1 << expr.bits) - 1
                return Const(
                    expr.idx, None, (expr.operands[0].value * expr.operands[1].value) & mask, expr.bits, **expr.tags
                )
            if {type(expr.operands[0]), type(expr.operands[1])} == {BinaryOp, Const}:
                op0, op1 = expr.operands
                const_, x0 = (op0, op1) if isinstance(op0, Const) else (op1, op0)
                if x0.op == "Mul" and (isinstance(x0.operands[0], Const) or isinstance(x0.operands[1], Const)):
                    # (A * x) * C => (A * C) * x
                    if isinstance(x0.operands[0], Const):
                        const_x0, x = x0.operands[0], x0.operands[1]
                    else:
                        const_x0, x = x0.operands[1], x0.operands[0]
                    new_const = Const(const_.idx, None, const_.value * const_x0.value, const_.bits, **const_x0.tags)
                    return BinaryOp(expr.idx, "Mul", [x, new_const], expr.signed, bits=expr.bits, **expr.tags)

        elif (
            expr.op == "Div"
            and isinstance(expr.operands[1], Const)
            and isinstance(expr.operands[0], BinaryOp)
            and expr.operands[0].op == "Mul"
            and isinstance(expr.operands[0].operands[1], Const)
        ):
            expr0, const_0 = expr.operands
            const_1 = expr0.operands[1]
            if const_0.value != 0 and const_1.value != 0:
                gcd_ = gcd(const_0.value, const_1.value)
                if gcd_ != 1:
                    new_const_1 = Const(
                        const_1.idx, const_1.variable, const_1.value // gcd_, const_1.bits, **const_1.tags
                    )
                    new_const_0 = Const(
                        const_0.idx, const_0.variable, const_0.value // gcd_, const_0.bits, **const_0.tags
                    )
                    mul = BinaryOp(
                        expr0.idx,
                        "Mul",
                        (expr0.operands[0], new_const_1),
                        expr0.signed,
                        variable=expr0.variable,
                        variable_offset=expr0.variable_offset,
                        bits=expr0.bits,
                        **expr0.tags,
                    )
                    return BinaryOp(expr.idx, "Div", (mul, new_const_0), expr.signed, bits=expr.bits, **expr.tags)

        elif expr.op == "Mod":
            op0, op1 = expr.operands
            if (
                isinstance(op0, Const)
                and isinstance(op0.value, int)
                and isinstance(op1, Const)
                and isinstance(op1.value, int)
                and op1.value != 0
            ):
                return Const(expr.idx, None, op0.value % op1.value, expr.bits, **expr.tags)

        elif expr.op in {"Shr", "Sar"} and isinstance(expr.operands[1], Const):
            expr0, expr1 = expr.operands
            if isinstance(expr0, BinaryOp) and expr0.op == "Shr" and isinstance(expr0.operands[1], Const):
                # (a >> M) >> N  ==>  a >> (M + N)
                const_a = expr0.operands[1]
                const_b = expr1
                const = Const(const_b.idx, None, const_a.value + const_b.value, const_b.bits, **const_b.tags)
                return BinaryOp(expr.idx, expr.op, (expr0.operands[0], const), False, bits=expr.bits, **expr.tags)

            if isinstance(expr0, BinaryOp) and expr0.op == "Div" and isinstance(expr0.operands[1], Const):
                # (a / M0) >> M1  ==>  a / (M0 * 2 ** M1)
                const_m0 = expr0.operands[1]
                const_m1 = expr1
                const = Const(const_m0.idx, None, const_m0.value * 2**const_m1.value, const_m0.bits, **const_m0.tags)
                return BinaryOp(expr.idx, "Div", (expr0.operands[0], const), expr.signed, bits=expr.bits, **expr.tags)

            if isinstance(expr0, Const):
                const_a = expr0.value
                mask = (2**expr0.bits) - 1
                return Const(expr0.idx, None, (const_a >> expr1.value) & mask, expr0.bits, **expr0.tags)

            if expr.op == "Shr" and expr.operands[0].bits <= expr.operands[1].value:
                return Const(expr.idx, None, 0, expr.operands[0].bits, **expr.tags)

        elif expr.op == "Shl" and isinstance(expr.operands[1], Const):
            expr0, expr1 = expr.operands
            if isinstance(expr0, Const):
                const_a = expr0.value
                mask = (2**expr0.bits) - 1
                return Const(expr0.idx, None, (const_a << expr1.value) & mask, expr0.bits, **expr0.tags)

        elif expr.op == "Or":
            op0, op1 = expr.operands
            if (
                isinstance(op0, Const)
                and isinstance(op0.value, int)
                and isinstance(op1, Const)
                and isinstance(op1.value, int)
            ):
                return Const(expr.idx, None, expr.operands[0].value | expr.operands[1].value, expr.bits, **expr.tags)
            if isinstance(expr.operands[0], Const) and expr.operands[0].value == 0:
                return expr.operands[1]
            if isinstance(expr.operands[1], Const) and expr.operands[1].value == 0:
                return expr.operands[0]
            if isinstance(expr.operands[0], Const) and expr.operands[0].value == (1 << expr.operands[0].bits) - 1:
                return expr.operands[0]
            if isinstance(expr.operands[1], Const) and expr.operands[1].value == (1 << expr.operands[1].bits) - 1:
                return expr.operands[1]
            if expr.operands[0].likes(expr.operands[1]):
                return expr.operands[0]

        elif expr.op == "Xor":
            op0, op1 = expr.operands
            if (
                isinstance(op0, Const)
                and isinstance(op0.value, int)
                and isinstance(op1, Const)
                and isinstance(op1.value, int)
            ):
                return Const(expr.idx, None, expr.operands[0].value ^ expr.operands[1].value, expr.bits, **expr.tags)

        elif expr.op in {"CmpEQ", "CmpLE", "CmpGE"}:
            if expr.operands[0].likes(expr.operands[1]):
                # x == x => 1
                return Const(expr.idx, None, 1, 1, **expr.tags)
            if isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
                if expr.op == "CmpEQ":
                    return Const(
                        expr.idx, None, 1 if expr.operands[0].value == expr.operands[1].value else 0, 1, **expr.tags
                    )
                if expr.op == "CmpLE":
                    return Const(
                        expr.idx, None, 1 if expr.operands[0].value <= expr.operands[1].value else 0, 1, **expr.tags
                    )
                if expr.op == "CmpGE":
                    return Const(
                        expr.idx, None, 1 if expr.operands[0].value >= expr.operands[1].value else 0, 1, **expr.tags
                    )

        elif expr.op in {"CmpNE", "CmpLT", "CmpGT"}:
            if expr.operands[0].likes(expr.operands[1]):
                # x != x => 0
                return Const(expr.idx, None, 0, 1, **expr.tags)
            if isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
                if expr.op == "CmpNE":
                    return Const(
                        expr.idx, None, 1 if expr.operands[0].value != expr.operands[1].value else 0, 1, **expr.tags
                    )
                if expr.op == "CmpLT":
                    return Const(
                        expr.idx, None, 1 if expr.operands[0].value < expr.operands[1].value else 0, 1, **expr.tags
                    )
                if expr.op == "CmpGT":
                    return Const(
                        expr.idx, None, 1 if expr.operands[0].value > expr.operands[1].value else 0, 1, **expr.tags
                    )

        return None

    @staticmethod
    def _optimize_unaryop(expr: UnaryOp):
        if expr.op == "Neg" and isinstance(expr.operand, Const) and isinstance(expr.operand.value, int):
            const_a = expr.operand.value
            mask = (2**expr.bits) - 1
            return Const(expr.idx, None, (~const_a) & mask, expr.bits, **expr.tags)

        return None

    @staticmethod
    def _optimize_convert(expr: Convert):
        if (
            isinstance(expr.operand, Const)
            and expr.operand.is_int
            and expr.from_type == Convert.TYPE_INT
            and expr.to_type == Convert.TYPE_INT
            and expr.from_bits > expr.to_bits
        ):
            assert isinstance(expr.operand.value, int)
            # truncation
            mask = (1 << expr.to_bits) - 1
            v = expr.operand.value & mask
            return Const(expr.idx, expr.operand.variable, v, expr.to_bits, **expr.operand.tags)
        if (
            isinstance(expr.operand, Const)
            and expr.operand.is_int
            and expr.from_type == Convert.TYPE_INT
            and expr.to_type == Convert.TYPE_INT
            and expr.from_bits <= expr.to_bits
        ):
            assert isinstance(expr.operand.value, int)
            if expr.is_signed is False:
                # unsigned extension
                return Const(expr.idx, expr.operand.variable, expr.operand.value, expr.to_bits, **expr.operand.tags)
            # signed extension
            v = sign_extend(expr.operand.value, expr.to_bits)
            return Const(expr.idx, expr.operand.variable, v, expr.to_bits, **expr.operand.tags)
        return None
