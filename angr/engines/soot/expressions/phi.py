from __future__ import annotations
import logging

from .base import SimSootExpr

l = logging.getLogger("angr.engines.soot.expressions.phi")


class SimSootExpr_Phi(SimSootExpr):
    def _execute(self):
        # One value will be defined, based on the taken path
        # We first try to take the value from the source block, otherwise we iterate to find a define value
        # One case in which the value is NOT in the source block is when the source block is in native code
        if hasattr(self.state.scratch.source, "block_idx"):
            local_values = [
                self._translate_value(v) for v, idx in self.expr.values if idx == self.state.scratch.source.block_idx
            ]
            if len(local_values) > 0:
                # fastpath
                local = local_values[0]
                value = self.state.memory.load(local, none_if_missing=True)
                self.expr = value
                return

        local_options = [self._translate_value(v) for v, idx in self.expr.values[::-1]]
        for local in local_options:
            value = self.state.memory.load(local, none_if_missing=True)
            if value is not None:
                self.expr = value
                return
