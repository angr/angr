
from .base import SimSootValue


class SimSootValue_ParamRef(SimSootValue):

    __slots__ = [ 'id', 'type', 'index' ]

    def __init__(self, method_fullname, index, type_):
        self.id = self._create_unique_id(method_fullname, index)
        self.index = index
        self.type = type_

    @staticmethod
    def _create_unique_id(method_fullname, index):
        return "%s.param_%d" % (method_fullname, index)

    @classmethod
    def from_sootvalue(cls, method_fullname, soot_value):
        return cls(method_fullname, soot_value.index, soot_value.type)

    def __repr__(self):
        return self.id
