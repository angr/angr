
from .base import SimSootExpr


class SimSootExpr_Unsupported(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Unsupported, self).__init__(expr, state)

    def _execute(self):
        pass
