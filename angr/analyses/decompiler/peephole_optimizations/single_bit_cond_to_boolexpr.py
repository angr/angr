from __future__ import annotations
from angr.ailment.expression import ITE, Convert, BinaryOp, Const

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
        else:
            cond_inner = expr.cond

        if isinstance(cond_inner, BinaryOp):
            optimized = False
            if (
                cond_inner.op == "Xor"
                and isinstance(cond_inner.operands[1], Const)
                and cond_inner.operands[1].value == 1
            ):
                # A ^ 1 ==> !A, if A is single-bit
                # A ^ 1 ==> A == 0, if A is multi-bit
                optimized = True
                op0, op1 = cond_inner.operands
                if isinstance(op0, BinaryOp) and op0.op in BinaryOp.COMPARISON_NEGATION:
                    new_cond = BinaryOp(
                        None,
                        BinaryOp.COMPARISON_NEGATION[op0.op],
                        [op0.operands[0], op0.operands[1]],
                        False,
                        **op0.tags,
                    )
                else:
                    new_cond = BinaryOp(
                        None,
                        "CmpEQ",
                        [op0, Const(None, None, 0, op0.bits)],
                        False,
                        **cond_inner.tags,
                    )
            else:
                # A ==> A, if A is single-bit
                # A ==> A == 1, if A is multi-bit
                if cond_inner.op in BinaryOp.COMPARISON_NEGATION:
                    new_cond = cond_inner
                else:
                    op0, op1 = cond_inner.operands
                    if cond_inner.op == "CmpEQ" and isinstance(op1, Const) and op1.value == 1:
                        new_cond = cond_inner
                    else:
                        optimized = True
                        new_cond = BinaryOp(
                            None,
                            "CmpEQ",
                            [cond_inner, Const(None, None, 1, cond_inner.bits)],
                            False,
                            **cond_inner.tags,
                        )
            return (
                ITE(
                    expr.idx,
                    new_cond,
                    expr.iffalse,
                    expr.iftrue,
                    variable=expr.variable,
                    variable_offset=expr.variable_offset,
                    **expr.tags,
                )
                if optimized
                else None
            )

        return None
