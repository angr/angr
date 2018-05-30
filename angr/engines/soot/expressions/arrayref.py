
import logging
from .base import SimSootExpr
from ..values import SimSootValue_ArrayRef, SimSootValue_IntConstant, SimSootValue_Local

l = logging.getLogger('angr.engines.soot.expressions.arrayref')

class SimSootExpr_ArrayRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_ArrayRef, self).__init__(expr, state)

    def _execute(self):
        base = self._translate_value(self.expr.base)
        array_ref_base = self.state.memory.load(base)
        # Kinda hacky way of doing this
        # First we get the reference to the base of the array
        # and if the base exist we create a new reference that points to the correct
        # element
        if array_ref_base is not None:
            idx = self._translate_value(self.expr.index)
            if isinstance(idx, SimSootValue_IntConstant):
                # idx is a constant
                idx_value = idx.value
            else:
                # idx is a variable
                # => load value from memory
                idx_value = self.state.memory.load(idx)
            array_ref = SimSootValue_ArrayRef(array_ref_base.heap_alloc_id, idx_value,
                                              array_ref_base.type, array_ref_base.size)
            self.expr = self.state.memory.load(array_ref)
        else:
            l.warning("Trying to access a non existing array! (%r)", self.expr)
