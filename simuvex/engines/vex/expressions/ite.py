from .base import SimIRExpr

class SimIRExpr_ITE(SimIRExpr):
    def _execute(self):
        cond = self._translate_expr(self._expr.cond)
        expr0 = self._translate_expr(self._expr.iffalse)
        exprX = self._translate_expr(self._expr.iftrue)

        self.expr = self.state.se.If(cond.expr == 0, expr0.expr, exprX.expr)
