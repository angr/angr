import logging

from .base import SimSootExpr

l = logging.getLogger(name=__name__)


class SimSootExpr_InstanceOf(SimSootExpr):
    def _execute(self):
        obj = self._translate_value(self.expr.value)
        self.expr = self.state.solver.StringV(obj.type) == self.state.solver.StringV(self.expr.check_type)
