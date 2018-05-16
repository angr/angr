
import logging
from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.arrayref')

class SimSootExpr_ArrayRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_ArrayRef, self).__init__(expr, state)

    def _execute(self):
        # Parse the expr to get a SimSootValue_ParamRef instance
        base = self._translate_value(self.expr.base)
        array_ref_base = self.state.memory.load(base)
        # Kinda hacky way of doing this
        # First we get the reference to the base of the array
        # and if the base exist we change the index to point to the
        # correct element
        if array_ref_base is not None:
            array_ref_base.index = self.expr.index.value
            self.expr = self.state.memory.load(array_ref_base)
        else:
            l.warning("Trying to access a non existing array! (%r)", self.expr)

