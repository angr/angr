from ailment.expression import Convert, BinaryOp, Const, ITE, Expression, Register

from .base import PeepholeOptimizationExprBase


class SarToSignedDiv(PeepholeOptimizationExprBase):
    """
    Simplify signed divisions that are optimized into bit shifts during compilation.
    """

    __slots__ = ()

    NAME = "(signed(expr)? expr + A ** 2 - 1: expr) >>s A => expr /s 2 ** A"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, stmt_idx: int = None, block=None):
        if expr.op == "Sar":
            if isinstance(expr.operands[1], Const):
                op0, const = expr.operands

                if isinstance(op0, Register) and stmt_idx is not None and block is not None:
                    # look back by one statement to find its definition
                    op0 = self.find_definition(op0, stmt_idx, block)
                    # TODO: Ensure the new op0 does not have any expressions that overlap with the old op0 (a register)

                const_value = const.value
                conv = None
                if isinstance(op0, Convert):
                    # unpack it
                    conv = op0
                    op0 = op0.operand

                if isinstance(op0, ITE):
                    r = self._check_signedness(op0.cond)
                    if r is not None:
                        is_signed, inner_bits, inner_expr = r
                        if is_signed:
                            signed_result, unsigned_result = op0.iftrue, op0.iffalse
                        else:
                            signed_result, unsigned_result = op0.iffalse, op0.iftrue
                        if inner_bits != inner_expr.bits:
                            # unpack if necessary
                            if isinstance(signed_result, Convert) and signed_result.to_bits == inner_bits:
                                signed_result = signed_result.operand
                            if isinstance(unsigned_result, Convert) and unsigned_result.to_bits == inner_bits:
                                unsigned_result = unsigned_result.operand
                        if (
                            isinstance(signed_result, BinaryOp)
                            and signed_result.op == "Add"
                            and isinstance(signed_result.operands[1], Const)
                            and signed_result.operands[1].value == 2**const_value - 1
                        ):
                            if unsigned_result.likes(signed_result.operands[0]) and unsigned_result.likes(inner_expr):
                                # fully matched!
                                if inner_bits != inner_expr.bits:
                                    converted_innerexpr = Convert(None, inner_expr.bits, inner_bits, False, inner_expr)
                                else:
                                    converted_innerexpr = inner_expr
                                r = BinaryOp(
                                    op0.idx,
                                    "Div",
                                    [
                                        converted_innerexpr,
                                        Const(None, None, 2**const_value, converted_innerexpr.bits),
                                    ],
                                    True,
                                    **inner_expr.tags,
                                )
                                if conv is not None:
                                    # wrap it up with a Convert again
                                    r = Convert(conv.idx, conv.from_bits, conv.to_bits, conv.is_signed, r, **conv.tags)
                                return r

        return None

    @staticmethod
    def _check_signedness(expr) -> tuple[bool, int, Expression] | None:
        # return a tuple of ( is_signed (False for is_unsigned), bits of the expression to test for signedness, and the
        # expression itself ).
        if isinstance(expr, BinaryOp):
            eq0, eq1 = False, False
            if isinstance(expr.operands[1], Const):
                if expr.op == "CmpEQ":
                    if expr.operands[1].value == 0:
                        eq0 = True
                    elif expr.operands[1].value == 1:
                        eq1 = True
                elif expr.op == "CmpNE":
                    if expr.operands[1].value == 1:
                        eq0 = True
                    elif expr.operands[1].value == 0:
                        eq1 = True
            if not eq0 and not eq1:
                return None

            if isinstance(expr.operands[0], BinaryOp) and expr.operands[0].op == "And":
                and_expr = expr.operands[0]
                if isinstance(and_expr.operands[1], Const) and and_expr.operands[1].value == 1:
                    # continue to match the shift
                    if isinstance(and_expr.operands[0], BinaryOp) and and_expr.operands[0].op == "Shr":
                        rshift_expr = and_expr.operands[0]
                        inner, right = rshift_expr.operands
                        if isinstance(right, Const) and right.value in {0xF, 0x1F, 0x3F}:
                            return eq1, right.value + 1, inner
        return None
