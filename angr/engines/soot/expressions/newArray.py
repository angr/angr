
from .base import SimSootExpr
from ..values import SimSootValue_ArrayRef


class SimSootExpr_NewArray(SimSootExpr):
    """
    Allocate a new array in memory and return the reference to that array
    """
    def __init__(self, expr, state):
        super(SimSootExpr_NewArray, self).__init__(expr, state)

    def _execute(self):
        array_size = self._translate_expr(self.expr.size).expr
        array_type = self.expr.base_type
        # arrays are stored on the heap
        # => create a unique reference
        heap_alloc_id = "%s_array_%s" % (array_type, self.state.memory.get_new_uuid())
        # return the reference of the base element
        # => elements as such getting lazy initialized in the javavm memory
        self.expr = SimSootValue_ArrayRef(heap_alloc_id, 0, array_type, array_size)
