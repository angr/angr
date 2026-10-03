from __future__ import annotations

from angr.ailment.expression import ITE, BinaryOp, Const, UnaryOp

from .base import PeepholeOptimizationExprBase


class RemoveRedundantITEComparisons(PeepholeOptimizationExprBase):
    """
    Remove redundant ITE comparisons.
    """

    __slots__ = ()

    NAME = "Remove redundant ITE comparisons"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        # SSE compare masks (ITE(cond, mask, 0) from a lane-wise compare):
        #   ITE(cond, m, 0) & 1  ==>  cond        ITE(cond, m, 0) & k  ==>  ITE(cond, m & k, 0)
        #   ITE(cond, m, 0) >u 0 ==>  cond
        if expr.op in {"And", "CmpGT"} and not expr.signed:
            ite, const = expr.operands
            if (
                isinstance(ite, ITE)
                and isinstance(const, Const)
                and isinstance(ite.iftrue, Const)
                and isinstance(ite.iffalse, Const)
                and isinstance(ite.iftrue.value, int)
                and isinstance(const.value, int)
                and ite.iftrue.value != 0
                and ite.iffalse.value == 0
            ):
                if expr.op == "CmpGT" and const.value == 0:
                    return ite.cond
                if expr.op == "And":
                    masked = ite.iftrue.value & const.value
                    if masked == 1:
                        return ite.cond
                    if masked != ite.iftrue.value:
                        masked_const = Const(self.manager.next_atom(), masked, ite.bits)
                        return ITE(expr.idx, ite.cond, masked_const, ite.iffalse, **expr.tags)

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
                return UnaryOp(self.manager.next_atom(), "Not", inner_expr.cond, **expr.tags)

        return None
