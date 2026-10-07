from __future__ import annotations

from angr.ailment.expression import ITE, BinaryOp, Const, Convert, Expression, UnaryOp

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
        #   ITE(cond, m, 0) >u 0 ==>  cond        ITE(cond, m, 0) <=u 0 ==>  !cond
        # (also through a truncating Conv of the mask, as long as the truncated mask is nonzero)
        if expr.op in {"And", "CmpGT", "CmpLE"} and not expr.signed:
            ite, const = expr.operands
            ite = self._truncated_ite(ite)
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
                if expr.op == "CmpLE" and const.value == 0:
                    return UnaryOp(self.manager.next_atom(), "Not", ite.cond, **expr.tags)
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

    def _truncated_ite(self, expr: Expression) -> Expression:
        """Conv(N->M, ITE(cond, C0, C1)) ==> ITE(cond, C0 mod 2^M, C1 mod 2^M)."""
        if not (
            isinstance(expr, Convert)
            and expr.from_type == expr.to_type == Convert.TYPE_INT
            and expr.to_bits < expr.from_bits
            and isinstance(expr.operand, ITE)
        ):
            return expr
        ite = expr.operand
        if not (
            isinstance(ite.iftrue, Const)
            and isinstance(ite.iffalse, Const)
            and isinstance(ite.iftrue.value, int)
            and isinstance(ite.iffalse.value, int)
        ):
            return expr
        mask = (1 << expr.to_bits) - 1
        return ITE(
            ite.idx,
            ite.cond,
            Const(self.manager.next_atom(), ite.iftrue.value & mask, expr.to_bits),
            Const(self.manager.next_atom(), ite.iffalse.value & mask, expr.to_bits),
            **ite.tags,
        )
