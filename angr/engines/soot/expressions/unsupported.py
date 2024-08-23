from __future__ import annotations
from .base import SimSootExpr


class SimSootExpr_Unsupported(SimSootExpr):
    def _execute(self):
        pass
