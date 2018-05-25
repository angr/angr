
from .base import SimSootExpr

class SimSootExpr_ThisRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_ThisRef, self).__init__(expr, state)

    def _execute(self):
        self.expr = self._translate_value(self.expr)

