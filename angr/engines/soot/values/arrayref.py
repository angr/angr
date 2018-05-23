
from .base import SimSootValue
from . import translate_value


class SimSootValue_ArrayRef(SimSootValue):

    __slots__ = ['index', 'type', 'base', 'size']

    def __init__(self, index, type_, base, size=None):
        self.id = self._create_unique_id(base, index)
        self.index = index
        self.type = type_
        self.base = base
        self.size = size

    @staticmethod
    def _create_unique_id(base, index):
        return "%s[%d]" % (base.id, index)

    @classmethod
    def from_sootvalue(cls, method_fullname, soot_value):
        fixed_base = translate_value(method_fullname, soot_value.base)
        return cls(soot_value.index.value, soot_value.type, fixed_base)

    def __repr__(self):
        return self.id
