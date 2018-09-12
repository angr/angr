
from .base import SimSootValue


class SimSootValue_StringRef(SimSootValue):

    __slots__ = [ 'id', 'type' ]

    def __init__(self, heap_alloc_id):
        self.id = "%s.string" % heap_alloc_id
        self.type = "java.lang.String"

    def __repr__(self):
        return self.id

    def __eq__(self, other):
        return isinstance(other, SimSootValue_StringRef) and \
               self.id == other.id and \
               self.type == other.type

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        raise NotImplementedError()
