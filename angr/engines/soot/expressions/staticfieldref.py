
import logging
from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.staticfieldref')

class SimSootExpr_StaticFieldRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_StaticFieldRef, self).__init__(expr, state)

    def _execute(self):
        static_ref = self._translate_value(self.expr)
        value = self.state.memory.load(static_ref)
        if value is not None:
            self.expr = value
        else:
            l.warning("Trying to get a Static Field not loaded (%r)", static_ref)
            # TODO: ask what to do for symbolic value and under constraint symbolic execution
            self.expr = self.state.project.simos.get_default_value_by_type(static_ref.type)
