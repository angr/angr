from __future__ import annotations
from .base import SimSootExpr


class SimSootExpr_ParamRef(SimSootExpr):
    def _execute(self):
        paramref = self._translate_value(self.expr)
        self.expr = self.state.memory.load(paramref, none_if_missing=True)
