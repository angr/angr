from __future__ import annotations
import logging

import claripy

from ..values import SimSootValue_ArrayBaseRef
from .base import SimSootExpr

l = logging.getLogger("angr.engines.soot.expressions.newarray")


class SimSootExpr_NewArray(SimSootExpr):
    def _execute(self):
        element_type = self.expr.base_type
        size = self._translate_expr(self.expr.size).expr
        self.expr = self.new_array(self.state, element_type, size)

    @staticmethod
    def new_array(state, element_type, size):
        """
        Allocates a new array in memory and returns the reference to the base.
        """
        size_bounded = SimSootExpr_NewArray._bound_array_size(state, size)
        # return the reference of the array base
        # => elements getting lazy initialized in the javavm memory
        return SimSootValue_ArrayBaseRef(
            heap_alloc_id=state.javavm_memory.get_new_uuid(), element_type=element_type, size=size_bounded
        )

    @staticmethod
    def _bound_array_size(state, array_size):
        # check if array size can exceed MAX_ARRAY_SIZE
        max_array_size = claripy.BVV(state.javavm_memory.max_array_size, 32)
        size_stays_below_maximum = state.solver.eval_upto(max_array_size.SGE(array_size), 2)

        # overwrite size, if it *always* exceeds the maximum
        if True not in size_stays_below_maximum:
            l.warning(
                "Array size %s always exceeds maximum size. It gets overwritten with the maximum %s.",
                array_size,
                max_array_size,
            )
            return max_array_size

        # bound size, if it *can* exceeds the maximum
        if True in size_stays_below_maximum and False in size_stays_below_maximum:
            l.warning(
                "Array size %s can exceed maximum size. It gets bounded with the maximum %s.",
                array_size,
                max_array_size,
            )
            state.solver.add(max_array_size.UGE(array_size))

        return array_size
