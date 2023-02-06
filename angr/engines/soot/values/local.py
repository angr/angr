from .base import SimSootValue


class SimSootValue_Local(SimSootValue):
    __slots__ = ["id", "type"]

    def __init__(self, name, type_):
        super().__init__()
        self.id = name
        self.type = type_

    def __repr__(self):
        return self.id

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        return cls(soot_value.name, soot_value.type)
