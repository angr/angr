from .base import SimSootValue
from . import translate_value


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
        return "%s[%d]" % (heap_alloc_id, index)

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        fixed_base = translate_value(soot_value.base, state)
        array_ref_base = state.memory.load(fixed_base)
        return cls(array_ref_base.heap_alloc_id, soot_value.index.value, soot_value.type, array_ref_base.size)

    def __repr__(self):
        return self.id
