import logging

from .base import SimSootExpr
from .newArray import SimSootExpr_NewArray
from ..values import SimSootValue_ArrayBaseRef

l = logging.getLogger('angr.engines.soot.expressions.newmultiarray')


class SimSootExpr_NewMultiArray(SimSootExpr):
    def _execute(self):
        # TODO: move this fix to pysoot
        # pysoot returns square brackets in the element type, which is inconsistent with respect to SimpleArray
        element_type = self.expr.base_type[:-2]
        sizes = [self._translate_expr(size).expr for size in self.expr.sizes]
        size = sizes.pop(0)
        self.expr = self.new_array(self.state, element_type, size, default_value_generator=
            lambda s: SimSootExpr_NewMultiArray._generate_inner_array(s, element_type, sizes))

    @staticmethod
    def new_array(state, element_type, size, default_value_generator=None):
        """
        Allocates a new multi array in memory and returns the reference to the base.
        """
        size_bounded = SimSootExpr_NewMultiArray._bound_multi_array_size(state, size)
        # return the reference of the array base
        # => elements getting lazy initialized in the javavm memory
        return SimSootValue_ArrayBaseRef(heap_alloc_id=state.javavm_memory.get_new_uuid(),
                                         element_type=element_type,
                                         size=size_bounded,
                                         default_value_generator=default_value_generator)

    @staticmethod
    def _bound_multi_array_size(state, multi_array_size):
        # check if array size can exceed MAX_ARRAY_SIZE
        max_multi_array_size = state.solver.BVV(state.javavm_memory.max_array_size, 32)
        size_stays_below_maximum = state.solver.eval_upto(
            max_multi_array_size.SGE(multi_array_size), 2
        )

        # overwrite size, if it *always* exceeds the maximum
        if not True in size_stays_below_maximum:
            l.warning('Array size %s always exceeds maximum size. '
                      'It gets overwritten with the maximum %s.',
                      multi_array_size, max_multi_array_size)
            return max_multi_array_size

        # bound size, if it *can* exceeds the maximum
        if True in size_stays_below_maximum and \
                False in size_stays_below_maximum:
            l.warning('Array size %s can exceed maximum size. '
                      'It gets bounded with the maximum %s.',
                      multi_array_size, max_multi_array_size)
            state.solver.add(max_multi_array_size.UGE(multi_array_size))

        return multi_array_size

    @staticmethod
    def _generate_inner_array(state, element_type, inner_sizes):
        # create a copy of the list
        inner_sizes = list(inner_sizes)
        size = inner_sizes.pop(0)
        element_type = element_type[:-2]

        if inner_sizes:
            # there are other inner sizes, we need to allocate a MultiArrayRef
            return SimSootExpr_NewMultiArray.new_array(state, element_type, size, default_value_generator=
                lambda s: SimSootExpr_NewMultiArray._generate_inner_array(s, element_type, inner_sizes))
        else:
            # otherwise, we allocate a simple Array
            return SimSootExpr_NewArray.new_array(state, element_type, size)
