from .base import SimSootExpr


class SimSootExpr_Length(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Length, self).__init__(expr, state)

    def _execute(self):
        operand = self._translate_expr(self.expr.value)
        # TODO: Can we have a symbolic length??
        if operand.expr.size is None:
            self.expr = self.state.se.BVS('len_%s' % operand.expr.base.name, 32)
        else:
            self.expr = self.state.se.BVV(operand.expr.size, 32)


