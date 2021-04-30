from ailment.expression import ITE, BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class RemoveRedundantITEBranches(PeepholeOptimizationExprBase):
    __slots__ = ()

    name = "Remove redundant ITE branches"
    expr_classes = (ITE, )  # all expressions are allowed

    def optimize(self, expr: ITE):

        # ITE(cond, a, ITE(!cond, b, c)) ==> ITE(cond, a, b)
        if isinstance(expr.iffalse, ITE):
            # cascading ITEs
            if isinstance(expr.cond, BinaryOp) and isinstance(expr.iffalse.cond, BinaryOp):
                # are they negating each other?
                if { expr.cond.op, expr.iffalse.cond.op } == {"CmpEQ", "CmpNE"}:
                    # FIXME: DON'T COMPARE STRINGS! Implement .likes() for all ailment.Expression classes!
                    condstr0 = repr(tuple(expr.cond.operands))
                    condstr1 = repr(tuple(expr.iffalse.cond.operands))
                    if condstr0 == condstr1:
                        # YES...
                        expr = ITE(expr.idx, expr.cond, expr.iffalse.iftrue, expr.iftrue, **expr.tags)
                        return expr

        return None
