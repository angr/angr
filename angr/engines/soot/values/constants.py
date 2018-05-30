from .base import SimSootValue

class SimSootValue_IntConstant(SimSootValue):

    __slots__ = [ 'value', 'type' ]

    def __init__(self, value, type_):
        super(SimSootValue_IntConstant, self).__init__()
        self.value = value
        self.type = type_

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        return cls(soot_value.value, soot_value.type)

    def __repr__(self):
        return self.value
