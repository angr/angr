from .base import SimSootValue
from . import translate_value
from .constants import SimSootValue_IntConstant
from claripy import And
from ....errors import SimEngineError

import logging
l = logging.getLogger('angr.engines.soot.values.arrayref')

class SimSootValue_ArrayRef(SimSootValue):

    __slots__ = ['index', 'type', 'size', 'id', 'heap_alloc_id']

    def __init__(self, heap_alloc_id, index, type_, size):
        self.id = self._create_unique_id(heap_alloc_id, index)
        self.heap_alloc_id = heap_alloc_id
        self.index = index
        self.type = type_
        self.size = size

    def __repr__(self):
        return self.id

    @staticmethod
    def get_arrayref_for_idx(base, idx):
        return SimSootValue_ArrayRef(base.heap_alloc_id, idx, base.type, base.size)
    
    @classmethod
    def from_sootvalue(cls, soot_value, state):
        fixed_base = translate_value(soot_value.base, state)
        array_ref_base = state.memory.load(fixed_base)
        idx = cls.translate_array_index(soot_value.index, state)
        cls.check_array_bounds(idx, array_ref_base, state)
        return cls(array_ref_base.heap_alloc_id, idx, soot_value.type, array_ref_base.size)

    @staticmethod
    def _create_unique_id(heap_alloc_id, index):
        return "%s[%s]" % (heap_alloc_id, str(index))

    @staticmethod
    def translate_array_index(idx, state):
        idx_value = translate_value(idx, state)
        if isinstance(idx_value, SimSootValue_IntConstant):
            # idx is a constant
            return idx_value.value
        else:
            # idx is a variable
            # => load value from memory
             return state.memory.load(idx_value)

    @staticmethod
    def check_array_bounds(idx, array, state):
        zero = state.solver.BVV(0, 32)
        length = array.size

        idx_stays_within_bounds = state.solver.eval_upto(
            And(length.SGT(idx), zero.SLE(idx)), 2
        )

        # There are 3 cases
        # 1) idx has only valid solutions
        # 2) idx has only invalid soultions
        #    TODO: raise a java.lang.ArrayIndexOutOfBoundsException
        # 3) idx has some valid and some invalid solutions
        #    TODO: split current SimState into two successors:
        #          --> one w/ all valid indexes
        #          --> one w/ all invalid indexes and a raised exception
        #
        # For now we just constraint the index to stay within the bounds

        # exist any valid solutions?
        if not True in idx_stays_within_bounds:
            raise SimEngineError("Access of %s[%s] (length %s) is always invalid. "
                                 "Cannot continue w/o raising java.lang.ArrayIndexOutOfBoundsException."
                                 % (array.heap_alloc_id, idx, length))
            
        # exist any out-of-bounds solutions?
        if False in idx_stays_within_bounds:
            l.warning("Possible out-of-bounds access! Index and/or length gets constraint to "
                      "valid values. (%s[%s], length %s)" % (array.heap_alloc_id, idx, length))
            state.solver.add(And(length.SGT(idx), zero.SLE(idx)))
