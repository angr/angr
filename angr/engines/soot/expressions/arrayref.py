
import logging
from .base import SimSootExpr
from ..values import SimSootValue_ArrayRef, SimSootValue_IntConstant, SimSootValue_Local, SimSootValue_ArrayRef

l = logging.getLogger('angr.engines.soot.expressions.arrayref')

class SimSootExpr_ArrayRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_ArrayRef, self).__init__(expr, state)

    def _execute(self):
        base = self._translate_value(self.expr.base)
        array_ref_base = self.state.memory.load(base)
        if array_ref_base is not None:
            # translate idx
            idx = SimSootValue_ArrayRef.translate_array_index(self.expr.index, self.state)
            # check idx against array bounds
            SimSootValue_ArrayRef.check_array_bounds(idx, array_ref_base, self.state)
            # load element
            array_ref = SimSootValue_ArrayRef.get_arrayref_for_idx(base=array_ref_base, idx=idx)
            self.expr = self.state.memory.load(array_ref)
        else:
            l.warning("Trying to access a non existing array! (%r)", self.expr)
