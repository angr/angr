from __future__ import annotations
import claripy

from ...engines.light.engine import SimEngineLightMixin


class TopCheckerMixin(SimEngineLightMixin):
    def _is_top(self, expr) -> bool:
        return bool(isinstance(expr, claripy.ast.Base) and "TOP" in expr.variables)

    def _top(self, size: int):
        return self.state.top(size)
