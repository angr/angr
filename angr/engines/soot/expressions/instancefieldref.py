
from .base import SimSootExpr

class SimSootExpr_InstanceFieldRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_InstanceFieldRef, self).__init__(expr, state)

    def _execute(self):
        field_ref = self._translate_value(self.expr)
        self.expr = self.state.memory.load(field_ref)
