from math import gcd

from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class EagerEvaluation(PeepholeOptimizationExprBase):
    """
    Eagerly evaluates certain types of expressions.
    """

    __slots__ = ()

    NAME = "Eager expression evaluation"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp):
        if expr.op == "Add" and isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
            mask = (2 << expr.bits) - 1
            new_expr = Const(
                expr.idx, None, (expr.operands[0].value + expr.operands[1].value) & mask, expr.bits, **expr.tags
            )
            return new_expr
        elif expr.op == "Sub" and isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
            mask = (2 << expr.bits) - 1
            new_expr = Const(
                expr.idx, None, (expr.operands[0].value - expr.operands[1].value) & mask, expr.bits, **expr.tags
            )
            return new_expr

        elif expr.op == "And" and isinstance(expr.operands[0], Const) and isinstance(expr.operands[1], Const):
            new_expr = Const(expr.idx, None, (expr.operands[0].value & expr.operands[1].value), expr.bits, **expr.tags)
            return new_expr

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

        elif expr.op == "Shl" and isinstance(expr.operands[1], Const):
            expr0, expr1 = expr.operands
            if isinstance(expr0, Const):
                const_a = expr0.value
                mask = (2**expr0.bits) - 1
                new_expr = Const(expr0.idx, None, (const_a << expr1.value) & mask, expr0.bits, **expr0.tags)
                return new_expr

        return None
