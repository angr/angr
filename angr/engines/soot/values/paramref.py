from __future__ import annotations
from .base import SimSootValue


class SimSootValue_ParamRef(SimSootValue):
    __slots__ = ["id", "index", "type"]

    def __init__(self, index, type_):
        self.id = "param_%d" % index
        self.index = index
        self.type = type_

    def __repr__(self):
        return self.id

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        return cls(soot_value.index, soot_value.type)
