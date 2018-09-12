
import logging

from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.phi')


class SimSootExpr_Phi(SimSootExpr):
    def _execute(self):
        locals_option = [self._translate_value(v) for v in self.expr.values]
        values = []
        for local in locals_option:
            value = self.state.memory.load(local, none_if_missing=True)
            if value is not None:
                values.append(value)

        if len(values) == 0:
            l.warning("Couldn't find a value of Phi expression in memory.")
            return

        if len(values) > 2:
            l.warning("Found multiple values of Phi expression in memory.")

        self.expr = values[-1]
