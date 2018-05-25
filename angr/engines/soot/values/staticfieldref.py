
from .base import SimSootValue


class SimSootValue_StaticFieldRef(SimSootValue):

    __slots__ = ['id', 'type', 'class_name', 'field_name']

    def __init__(self, class_name, field_name, type_):
        self.id = self._create_unique_id(class_name, field_name)
        self.class_name = class_name
        self.field_name = field_name
        self.type = type_

    @staticmethod
    def _create_unique_id(class_name, field_name):
        return "%s.%s" % (class_name, field_name)

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        return cls(soot_value.field[1], soot_value.field[0], soot_value.type)

    def __repr__(self):
        return self.id
