
from .base import SimSootExpr


class SimSootExpr_IntConstant(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_IntConstant, self).__init__(expr, state)

    def _execute(self):
        self.expr = self.state.se.BVV(self.expr.value, 32)

class SimSootExpr_StringConstant(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_StringConstant, self).__init__(expr, state)

    def _execute(self):
        # We need to strip away the quotes introduced by soot in case of a string constant
        self.expr = self.state.se.StringV(self.expr.value.strip("\""))

# TODO add other constants

