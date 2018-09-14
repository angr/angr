from .base import SimIRExpr

import logging
l = logging.getLogger("angr.engines.vex.expressions.unsupported")

class SimIRExpr_Unsupported(SimIRExpr):
    def _execute(self):
        l.error("Unsupported IRExpr %s. Please implement.", type(self._expr).__name__)
        self.expr = self.state.solver.Unconstrained(type(self._expr).__name__, self.size_bits())
        self.state.history.add_event('resilience', resilience_type='irexpr', expr=type(self._expr).__name__, message='unsupported irexpr')
