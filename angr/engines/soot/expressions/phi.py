
import logging

from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.phi')


class SimSootExpr_Phi(SimSootExpr):
    def _execute(self):
        try:
            local = [self._translate_value(v) for v, idx in self.expr.values if idx == self.state.scratch.source.block_idx][0]
            value = self.state.memory.load(local, none_if_missing=True)
            self.expr = value
        except IndexError:
            # TODO is there a better way to do this?
            local_options = [self._translate_value(v) for v, idx in self.expr.values[::-1]]
            for local in local_options:
                value = self.state.memory.load(local, none_if_missing=True)
                if value is not None:
                    self.expr = value
                    return

