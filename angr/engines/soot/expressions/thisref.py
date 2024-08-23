from __future__ import annotations
from .base import SimSootExpr


class SimSootExpr_ThisRef(SimSootExpr):
    def _execute(self):
        self.expr = self._translate_value(self.expr)
