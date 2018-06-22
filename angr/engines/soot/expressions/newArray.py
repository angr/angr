
from .base import SimSootExpr
from ..values import SimSootValue_ArrayRef

import logging
l = logging.getLogger('angr.engines.soot.expressions.newarray')

class SimSootExpr_NewArray(SimSootExpr):

    def __init__(self, expr, state):
        super(SimSootExpr_NewArray, self).__init__(expr, state)

    def _execute(self):
        base_type = self.expr.base_type
        size = self._translate_expr(self.expr.size).expr
        self.expr = self.new_array(self.state, base_type, size)

    @staticmethod
    def new_array(state, base_type, size):
        """
        Allocates a new array in memory and returns the reference of the base element.
        """
        size_bounded = SimSootExpr_NewArray._bound_array_size(state, size)
        # arrays are stored on the heap
        # => create a unique reference 
        heap_alloc_id = "{uuid}.{base_type}_array".format(base_type=base_type,
                                                          uuid=state.javavm_memory.get_new_uuid())
        # return the reference of the base element
        # => elements as such getting lazy initialized in the javavm memory
        return SimSootValue_ArrayRef(heap_alloc_id, 0, base_type, size_bounded)

    @staticmethod
    def _bound_array_size(state, array_size):

        # check if array size can exceed MAX_ARRAY_SIZE
        max_array_size = state.solver.BVV(state.javavm_memory.max_array_size, 32)
        size_exceeds_maximum = state.solver.eval_upto(
            max_array_size.SGE(array_size), 2
        )

        # overwrite size, if it *always* exceeds the maximum
        if not True in size_exceeds_maximum:
            l.warning("Array size %s always execeeds maximum. "
                      "It gets overwritten with the maximum %s."
                       % (array_size, max_array_size))
            return max_array_size

        # bound size, if it *can* exceeds the maximum
        if True  in size_exceeds_maximum and\
           False in size_exceeds_maximum:
            l.warning("Array size %s can execeed maximum. "
                      "It gets bounded with the maximum %s."
                       % (array_size, max_array_size))
            state.solver.add(max_array_size.SGE(array_size))

        return array_size