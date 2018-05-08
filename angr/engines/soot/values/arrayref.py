
from .base import SimSootValue


class SimSootValue_ArrayRef(SimSootValue):

    __slots__ = ['index', 'type', 'base', 'size']

    def __init__(self, index, type_, base, size=None):
        self.index = index
        self.type = type_
        self.base = base
        self.size = size

    @classmethod
    def from_sootvalue(cls, soot_value):
        return cls(soot_value.index.value, soot_value.type, soot_value.base)

    def __repr__(self):
        return "%s[%r]" % (self.base.name, self.index)
