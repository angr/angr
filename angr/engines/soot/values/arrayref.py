from .base import SimSootValue
from . import translate_value
from .constants import SimSootValue_IntConstant


class SimSootValue_ArrayRef(SimSootValue):

    __slots__ = ['index', 'type', 'size', 'id', 'heap_alloc_id']

    def __init__(self, heap_alloc_id, index, type_, size):
        self.id = self._create_unique_id(heap_alloc_id, index)
        self.heap_alloc_id = heap_alloc_id
        self.index = index
        self.type = type_
        self.size = size

    @staticmethod
    def _create_unique_id(heap_alloc_id, index):
        return "%s[%s]" % (heap_alloc_id, str(index))

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        fixed_base = translate_value(soot_value.base, state)
        array_ref_base = state.memory.load(fixed_base)
        idx = translate_value(soot_value.index, state)
        if isinstance(idx, SimSootValue_IntConstant):
            # idx is a constant
            idx_value = idx.value
        else:
            # idx is a variable
            # => load value from memory
            idx_value = state.memory.load(idx)
        return cls(array_ref_base.heap_alloc_id, idx_value, soot_value.type, array_ref_base.size)

    def __repr__(self):
        return self.id
