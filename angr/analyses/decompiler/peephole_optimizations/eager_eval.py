from math import gcd

from ailment.expression import BinaryOp, UnaryOp, Const, Convert, StackBaseOffset

from .base import PeepholeOptimizationExprBase


class EagerEvaluation(PeepholeOptimizationExprBase):
    """
    Eagerly evaluates certain types of expressions.
    """

    __slots__ = ()

    NAME = "Eager expression evaluation"
    expr_classes = (BinaryOp, UnaryOp, Convert)

    def optimize(self, expr, **kwargs):
        if isinstance(expr, BinaryOp):
            return self._optimize_binaryop(expr)
        elif isinstance(expr, Convert):
            return self._optimize_convert(expr)
        elif isinstance(expr, UnaryOp):
            return self._optimize_unaryop(expr)
        return None

    @staticmethod
    def _optimize_binaryop(expr: BinaryOp):
        if expr.op == "Add":
            if isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
                mask = (1 << expr.bits) - 1
                new_expr = Const(
                    expr.idx, None, (expr.operands[0].value + expr.operands[1].value) & mask, expr.bits, **expr.tags
                )
                return new_expr
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
                elif left.op == "Sub":
                    return BinaryOp(
                        left.idx,
                        "Add",
                        [inner_expr, Const(const_0.idx, None, const_1.value - const_0.value, const_0.bits)],
                        expr.signed,
                        **expr.tags,
                    )
            if (
                isinstance(expr.operands[0], BinaryOp)
                and expr.operands[0].op == "Mul"
                and isinstance(expr.operands[0].operands[1], Const)
                and expr.operands[0].operands[0].likes(expr.operands[1])
            ):
                # A * x + x => (A + 1) * x
                coeff_expr = expr.operands[0].operands[1]
                new_coeff = coeff_expr.value + 1
                return BinaryOp(
                    expr.idx,
                    "Mul",
                    [Const(coeff_expr.idx, None, new_coeff, coeff_expr.bits), expr.operands[1]],
                    expr.signed,
                    **expr.tags,
                )
        elif expr.op == "Sub":
            if isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
                mask = (1 << expr.bits) - 1
                new_expr = Const(
                    expr.idx, None, (expr.operands[0].value - expr.operands[1].value) & mask, expr.bits, **expr.tags
                )
                return new_expr
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
                elif left.op == "Sub":
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
                return Const(expr.idx, None, expr.operands[0].offset - expr.operands[1].offset, expr.bits, **expr.tags)

        elif expr.op == "And":
            if isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
                new_expr = Const(
                    expr.idx, None, (expr.operands[0].value & expr.operands[1].value), expr.bits, **expr.tags
                )
                return new_expr
            if isinstance(expr.operands[1], Const) and expr.operands[1].value == 0:
                return Const(expr.idx, None, 0, expr.bits, **expr.tags)

        elif expr.op == "Mul" and isinstance(expr.operands[1], Const) and expr.operands[1].value == 1:
            return expr.operands[0]

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
                    div = BinaryOp(expr.idx, "Div", (mul, new_const_0), expr.signed, bits=expr.bits, **expr.tags)
                    return div

        elif expr.op in {"Shr", "Sar"} and isinstance(expr.operands[1], Const):
            expr0, expr1 = expr.operands
            if isinstance(expr0, BinaryOp) and expr0.op == "Shr" and isinstance(expr0.operands[1], Const):
                # (a >> M) >> N  ==>  a >> (M + N)
                const_a = expr0.operands[1]
                const_b = expr1
                const = Const(const_b.idx, None, const_a.value + const_b.value, const_b.bits, **const_b.tags)
                new_expr = BinaryOp(expr.idx, expr.op, (expr0.operands[0], const), False, bits=expr.bits, **expr.tags)
                return new_expr

            if isinstance(expr0, BinaryOp) and expr0.op == "Div" and isinstance(expr0.operands[1], Const):
                # (a / M0) >> M1  ==>  a / (M0 * 2 ** M1)
                const_m0 = expr0.operands[1]
                const_m1 = expr1
                const = Const(const_m0.idx, None, const_m0.value * 2**const_m1.value, const_m0.bits, **const_m0.tags)
                new_expr = BinaryOp(
                    expr.idx, "Div", (expr0.operands[0], const), expr.signed, bits=expr.bits, **expr.tags
                )
                return new_expr

            if isinstance(expr0, Const):
                const_a = expr0.value
                mask = (2**expr0.bits) - 1
                new_expr = Const(expr0.idx, None, (const_a >> expr1.value) & mask, expr0.bits, **expr0.tags)
                return new_expr

            if expr.op == "Shr" and expr.operands[0].bits <= expr.operands[1].value:
                return Const(expr.idx, None, 0, expr.operands[0].bits, **expr.tags)

        elif expr.op == "Shl" and isinstance(expr.operands[1], Const):
            expr0, expr1 = expr.operands
            if isinstance(expr0, Const):
                const_a = expr0.value
                mask = (2**expr0.bits) - 1
                new_expr = Const(expr0.idx, None, (const_a << expr1.value) & mask, expr0.bits, **expr0.tags)
                return new_expr

        elif expr.op == "Or":
            if isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
                return Const(expr.idx, None, expr.operands[0].value | expr.operands[1].value, expr.bits, **expr.tags)
            if isinstance(expr.operands[0], Const) and expr.operands[0].value == 0:
                return expr.operands[1]
            if isinstance(expr.operands[1], Const) and expr.operands[1].value == 0:
                return expr.operands[0]
            if expr.operands[0].likes(expr.operands[1]):
                return expr.operands[0]

        return None

    @staticmethod
    def _optimize_unaryop(expr: UnaryOp):
        if expr.op == "Neg" and isinstance(expr.operand, Const):
            const_a = expr.operand.value
            mask = (2**expr.bits) - 1
            new_expr = Const(expr.idx, None, (~const_a) & mask, expr.bits, **expr.tags)
            return new_expr

        return None

    @staticmethod
    def _optimize_convert(expr: Convert):
        if isinstance(expr.operand, Const):
            if expr.from_bits > expr.to_bits:
                # truncation
                mask = (1 << expr.to_bits) - 1
                v = expr.operand.value & mask
                return Const(expr.idx, expr.operand.variable, v, expr.to_bits, **expr.operand.tags)
        return None
