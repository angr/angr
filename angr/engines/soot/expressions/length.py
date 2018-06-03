from .base import SimSootExpr


class SimSootExpr_Length(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Length, self).__init__(expr, state)

    def _execute(self):
        operand = self._translate_expr(self.expr.value)
        self.expr = operand.expr.size
