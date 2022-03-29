from ailment.expression import BinaryOp, Convert, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove redundant conversions around binary operators"
    expr_classes = (BinaryOp, )

    def optimize(self, expr: BinaryOp):

        if isinstance(expr.operands[0], Convert):
            if (expr.operands[0].to_bits == 32  # converting to an int
                and isinstance(expr.operands[1], Const)
            ):
                if expr.op == "And":
                    if expr.operands[0].from_bits == 16 and expr.operands[1].value <= 0xffff:
                        con = Const(None, None, expr.operands[1].value, 16, **expr.operands[1].tags)
                        new_expr = BinaryOp(expr.idx, "And", (expr.operands[0].operand, con), expr.signed,
                                        bits=16, **expr.tags)
                        return Convert(expr.operands[0].idx, 16, 32, expr.operands[0].is_signed, new_expr,
                                       **expr.operands[0].tags)
                    elif expr.operands[0].from_bits == 8 and expr.operands[1].value <= 0xff:
                        con = Const(None, None, expr.operands[1].value, 8, **expr.operands[1].tags)
                        new_expr = BinaryOp(expr.idx, "And", (expr.operands[0].operand, con), expr.signed,
                                        bits=8, **expr.tags)
                        return Convert(expr.operands[0].idx, 8, 32, expr.operands[0].is_signed, new_expr,
                                       **expr.operands[0].tags)

                elif expr.op in {"CmpEQ", "CmpNE", "CmpGT", "CmpGE", "CmpGTs", "CmpGEs", "CmpLT", "CmpLE", "CmpLTs", "CmpLEs"}:
                    if expr.operands[0].from_bits == 16 and expr.operands[1].value <= 0xffff:
                        con = Const(None, None, expr.operands[1].value, 16, **expr.operands[1].tags)
                        new_expr = BinaryOp(expr.idx, expr.op, (expr.operands[0].operand, con), expr.signed,
                                            bits=16, **expr.tags)
                        return new_expr
                    elif expr.operands[0].from_bits == 8 and expr.operands[1].value <= 0xff:
                        con = Const(None, None, expr.operands[1].value, 8, **expr.operands[1].tags)
                        new_expr = BinaryOp(expr.idx, expr.op, (expr.operands[0].operand, con), expr.signed,
                                            bits=8, **expr.tags)
                        return new_expr

            elif (isinstance(expr.operands[1], Convert)
                  and expr.operands[1].to_bits == expr.operands[0].to_bits
                  and expr.operands[1].from_bits == expr.operands[0].from_bits
            ):
                if expr.op in {"Add", "Sub"}:
                    op0 = expr.operands[0]
                    op0_inner = expr.operands[0].operand
                    # op1 = expr.operands[1]
                    op1_inner = expr.operands[1].operand

                    new_expr = BinaryOp(expr.idx, expr.op, (op0_inner, op1_inner), expr.signed,
                                        bits=op0.from_bits, **expr.tags,
                                        )
                    r = Convert(expr.idx, op0.from_bits, op0.to_bits, op0.is_signed, new_expr,
                                **op0.tags,
                                )
                    return r

        return None
