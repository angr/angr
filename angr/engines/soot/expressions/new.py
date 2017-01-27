
from .base import SimSootExpr


class SimSootExpr_New(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_New, self).__init__(expr, state)

    def _execute(self):
        type_ = self.expr.type
        # TODO: Create a new Java class
        # self.expr =
