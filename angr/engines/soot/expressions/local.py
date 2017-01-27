
from .base import SimSootExpr


class SimSootExpr_Local(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Local, self).__init__(expr, state)

    def _execute(self):

        # Parse the expr to get a SimSootValue_Local instance
        local = self._translate_value(self.expr)

        # Load the value from the stack
        self.expr = self.state.memory.load(local)
