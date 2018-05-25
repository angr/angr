
from .base import SimSootValue

# TODO: this class, as of now, is exactly the same as paramref. In fact
#       "this" is just syntactic sugar that inject the reference to the
#       object as the first parameter of the called method
#
#       SHOULD WE USE SimSootValue_ParamRef and get rid of this class?
class SimSootValue_ThisRef(SimSootValue):

    __slots__ = [ 'id', 'type' ]

    def __init__(self, heap_alloc_id, type_):
        self.id = heap_alloc_id
        self.type = type_

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        # TODO: Implement this
        return cls(state, soot_value.type)

    def __repr__(self):
        return self.id