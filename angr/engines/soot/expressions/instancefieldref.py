from .base import SimSootExpr


class SimSootExpr_InstanceFieldRef(SimSootExpr):
    def _execute(self):
        field_ref = self._translate_value(self.expr)
        self.expr = self.state.memory.load(field_ref, none_if_missing=True)
