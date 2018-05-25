
from .base import SimSootValue


class SimSootValue_ParamRef(SimSootValue):

    __slots__ = [ 'id', 'type', 'index' ]

    def __init__(self, index, type_):
        self.id = "param_%d" % index
        self.index = index
        self.type = type_

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        return cls(soot_value.index, soot_value.type)

    def __repr__(self):
        return self.id
