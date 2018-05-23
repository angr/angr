
from .base import SimSootValue


class SimSootValue_Local(SimSootValue):

    __slots__ = [ 'id', 'type', 'local_name' ]

    def __init__(self, method_fullname, local_name, type_):
        super(SimSootValue_Local, self).__init__()
        self.id = self._create_unique_id(method_fullname, local_name)
        self.local_name = local_name
        self.type = type_

    @staticmethod
    def _create_unique_id(method_fullname, local_name):
        return "%s.%s" % (method_fullname, local_name)

    @classmethod
    def from_sootvalue(cls, method_fullname, soot_value):
        return cls(method_fullname, soot_value.name, soot_value.type)

    def __repr__(self):
        return self.id
