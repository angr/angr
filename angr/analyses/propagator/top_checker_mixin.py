import claripy

from ...engines.light.engine import SimEngineLightMixin


class TopCheckerMixin(SimEngineLightMixin):
    def _is_top(self, expr) -> bool:
        if isinstance(expr, claripy.ast.Base):
            if "TOP" in expr.variables:
                return True
        return False

    def _top(self, size: int):
        return self.state.top(size)
