
from .base import SimSootValue
from . import translate_value


class SimSootValue_ArrayRef(SimSootValue):

    __slots__ = ['index', 'type', 'base', 'size']

    def __init__(self, index, type_, base, size=None):
        self.index = index
        self.type = type_
        self.base = base
        self.size = size

    @classmethod
    def from_sootvalue(cls, soot_value):
        fixed_base = translate_value(soot_value.base)
        return cls(soot_value.index.value, soot_value.type, fixed_base)

    def __repr__(self):
        return "%s[%r]" % (self.base.name, self.index)
