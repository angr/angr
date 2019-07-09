
import logging

from ..values import SimSootValue_ArrayRef
from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.arrayref')


class SimSootExpr_ArrayRef(SimSootExpr):

    def _execute(self):
        array_base_local = self._translate_value(self.expr.base)
        array_base = self.state.memory.load(array_base_local)
        if array_base is not None:
            # translate idx and check against array bounds
            idx = SimSootValue_ArrayRef.translate_array_index(self.expr.index, self.state)
            SimSootValue_ArrayRef.check_array_bounds(idx, array_base, self.state)
            # load element
            array_ref = SimSootValue_ArrayRef(array_base, idx)
            self.expr = self.state.memory.load(array_ref)
        else:
            l.warning("Trying to access a non existing array! (%r)", self.expr)
