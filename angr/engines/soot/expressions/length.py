from __future__ import annotations
from .base import SimSootExpr


class SimSootExpr_Length(SimSootExpr):
    def _execute(self):
        operand = self._translate_expr(self.expr.value)
        self.expr = operand.expr.size
