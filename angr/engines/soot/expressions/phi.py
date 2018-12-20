
import logging

from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.phi')


class SimSootExpr_Phi(SimSootExpr):
    def _execute(self):
        local = [self._translate_value(v) for v, idx in self.expr.values if idx == self.state.scratch.source.block_idx][0]
        value = self.state.memory.load(local, none_if_missing=True)
        self.expr = value
