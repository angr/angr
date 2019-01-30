from .base import SimIRExpr


class SimIRExpr_ITE(SimIRExpr):

    __slots__ = []

    def _execute(self):
        cond = self._translate_expr(self._expr.cond)
        expr0 = self._translate_expr(self._expr.iffalse)
        exprX = self._translate_expr(self._expr.iftrue)

        self.expr = self.state.solver.If(cond.expr == 0, expr0.expr, exprX.expr)
