from .base import SimIRExpr

import logging
l = logging.getLogger('simuvex.vex.expressions.unsupported')

class SimIRExpr_Unsupported(SimIRExpr):
    def _execute(self):
        l.error("Unsupported IRExpr %s. Please implement.", type(self._expr).__name__)
        self.expr = self.state.se.Unconstrained(type(self._expr).__name__, self.size_bits())
        self.state.log.add_event('resilience', resilience_type='irexpr', expr=type(self._expr).__name__, message='unsupported irexpr')
