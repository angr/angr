from __future__ import annotations
from .base import SimSootValue


class SimSootValue_IntConstant(SimSootValue):
    __slots__ = ["value", "type"]

    def __init__(self, value, type_):
        super().__init__()
        self.value = value
        self.type = type_

    def __repr__(self):
        return self.value

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        return cls(soot_value.value, soot_value.type)
