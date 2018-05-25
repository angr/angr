
from .base import SimSootExpr
from ..values import SimSootValue_ArrayRef


class SimSootExpr_NewArray(SimSootExpr):
    """
    Allocate a new array in memory and return the reference to that array
    """
    def __init__(self, expr, state):
        super(SimSootExpr_NewArray, self).__init__(expr, state)

    def _execute(self):
        # TODO: Handle different types of array
        # Size can be symbolic
        array_size = self._translate_expr(self.expr.size).expr
        if self.state.se.symbolic(array_size):
            size = self.state.memory.max_array_size
        else:
            size = self.state.se.eval(array_size)
        # Store  the array on the heap and return the reference
        # to the base element
        heap_alloc_id = self.state.memory.get_new_uuid()
        for idx in range(size):
            ref = SimSootValue_ArrayRef(heap_alloc_id, idx, self.expr.type, size)
            self.state.memory.store(ref, self.state.se.BVV(0, 32))
        base_ref = SimSootValue_ArrayRef(heap_alloc_id, 0, type, size)
        self.expr = base_ref

