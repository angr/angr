
from .base import SimSootValue


class SimSootValue_Local(SimSootValue):

    __slots__ = [ 'name', 'type' ]

    def __init__(self, name, type_):
        super(SimSootValue_Local, self).__init__()

        self.name = name
        self.type = type_

    @classmethod
    def from_sootvalue(cls, soot_value):
        return cls(soot_value.name, soot_value.type)

    def __repr__(self):
        return self.name
