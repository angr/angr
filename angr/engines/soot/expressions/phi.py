
from .base import SimSootExpr


class SimSootExpr_Phi(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Phi, self).__init__(expr, state)

    def _execute(self):

        if len(self.expr.values) != 2:
            import ipdb; ipdb.set_trace();

        v1, v2 = [self._translate_value(v) for v in self.expr.values]
        v = self.expr = self.state.memory.load(v1, none_if_missing=True)
        if v is None:
            v = self.expr = self.state.memory.load(v2, none_if_missing=True)
        if v is None:
            import ipdb; ipdb.set_trace();

        self.expr = v
