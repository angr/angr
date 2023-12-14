from ailment.expression import ITE, BinaryOp, UnaryOp, Const

from .base import PeepholeOptimizationExprBase


class RemoveRedundantITEComparisons(PeepholeOptimizationExprBase):
    """
    Remove redundant ITE comparisons.
    """

    __slots__ = ()

    NAME = "Remove redundant ITE comparisons"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        # ITE(cond, a, b) == a  ==>  cond
        # ITE(cond, a, b) == b  ==>  !cond
        # ITE(cond, a, b) != a  ==>  !cond
        # ITE(cond, a, b) != b  ==>  cond
        if expr.op == "CmpEQ":
            if isinstance(expr.operands[0], UnaryOp) and expr.operands[0].op == "Not":
                negate = True
                inner_expr = expr.operands[0].operand
            else:
                negate = False
                inner_expr = expr.operands[0]
        elif expr.op == "CmpNE":
            if isinstance(expr.operands[0], UnaryOp) and expr.operands[0].op == "Not":
                negate = False
                inner_expr = expr.operands[0].operand
            else:
                negate = True
                inner_expr = expr.operands[0]
        else:
            negate = None
            inner_expr = None

        if inner_expr is not None and isinstance(inner_expr, ITE):
            a, b = inner_expr.iftrue, inner_expr.iffalse
            if isinstance(expr.operands[1], Const):
                if isinstance(a, Const) and a.value == expr.operands[1].value:
                    pass
                elif isinstance(b, Const) and b.value == expr.operands[1].value:
                    negate = not negate
                else:
                    return None

                if not negate:
                    return inner_expr.cond
                else:
                    return UnaryOp(None, "Not", inner_expr.cond, **expr.tags)

        return None
