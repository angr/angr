
from .base import SimSootExpr


class SimSootExpr_Local(SimSootExpr):
    def _execute(self):
        local = self._translate_value(self.expr)
        self.expr = self.state.javavm_memory.load(local, none_if_missing=True)
