from ailment.expression import ITE, Convert, BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class SingleBitCondToBoolExpr(PeepholeOptimizationExprBase):
    """
    Convert single-bit conditions to bool expressions
    """

    __slots__ = ()

    NAME = "Convert single-bit conditions to bool expressions (== 0 or == 1)"
    expr_classes = (ITE,)

    def optimize(self, expr: ITE, **kwargs):
        if isinstance(expr.cond, Convert) and expr.cond.to_bits == 1 and expr.cond.from_bits > 1:
            cond_inner = expr.cond.operand
            if isinstance(cond_inner, BinaryOp):
                if (
                    cond_inner.op == "Xor"
                    and isinstance(cond_inner.operands[1], Const)
                    and cond_inner.operands[1].value == 1
                ):
                    # A ^ 1 ==> A == 0
                    new_cond = BinaryOp(
                        None,
                        "CmpEQ",
                        [cond_inner.operands[0], Const(None, None, 0, cond_inner.operands[0].bits)],
                        False,
                        **cond_inner.tags,
                    )
                else:
                    # A ==> A == 1
                    new_cond = BinaryOp(
                        None,
                        "CmpEQ",
                        [cond_inner.operands[0], Const(None, None, 1, cond_inner.operands[0].bits)],
                        False,
                        **cond_inner.tags,
                    )
                return ITE(
                    expr.idx,
                    new_cond,
                    expr.iffalse,
                    expr.iftrue,
                    variable=expr.variable,
                    variable_offset=expr.variable_offset,
                    **expr.tags,
                )

        return expr
