
from .base import SimSootExpr


class SimSootExpr_ArrayRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_ArrayRef, self).__init__(expr, state)

    def _execute(self):
        # Parse the expr to get a SimSootValue_ParamRef instance
        base = self._translate_value(self.expr.base)
        self.expr = self.state.memory.load(base)
