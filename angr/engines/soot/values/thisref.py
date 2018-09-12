
from .base import SimSootValue
from .local import SimSootValue_Local


class SimSootValue_ThisRef(SimSootValue):

    __slots__ = [ 'id', 'type' ]

    def __init__(self, heap_alloc_id, type_):
        self.id = "%s.%s.this" % (heap_alloc_id, type_)
        self.heap_alloc_id = heap_alloc_id
        self.type = type_

    def __repr__(self):
        return self.id

    def __eq__(self, other):
        return isinstance(other, SimSootValue_ThisRef) and \
               self.id == other.id and \
               self.heap_alloc_id == other.heap_alloc_id and \
               self.type == other.type

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        local = SimSootValue_Local("this", soot_value.type)
        return state.memory.load(local, none_if_missing=True)
