
from .base import SimSootValue


class SimSootValue_ParamRef(SimSootValue):

    __slots__ = [ 'index', 'type' ]

    def __init__(self, index, type_):
        self.index = index
        self.type = type_

    @classmethod
    def from_sootvalue(cls, soot_value):
        return cls(soot_value.index, soot_value.type)

    def __repr__(self):
        return "Parameter[%d]" % self.index
