
import logging
from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.instancefieldref')


class SimSootExpr_InstanceFieldRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_InstanceFieldRef, self).__init__(expr, state)

    def _execute(self):
        instance_ref = self._translate_value(self.expr)
        value = self.state.memory.load(instance_ref)
        if value is not None:
            self.expr = value
        else:
            l.warning("Trying to get a instance Field not loaded (%r)", instance_ref)
            # TODO: ask what to do for symbolic value and under constraint symbolic execution
            self.expr = self.state.project.simos.get_default_value_by_type(instance_ref.type)
