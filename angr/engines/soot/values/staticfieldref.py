
from .base import SimSootValue


class SimSootValue_StaticFieldRef(SimSootValue):

    __slots__ = ['field', 'type']

    def __init__(self, class_name, field_name, type_):
        self.field = class_name + "." + field_name
        self.type = type_

    @classmethod
    def from_sootvalue(cls, soot_value):
        return cls(soot_value.field[1], soot_value.field[0], soot_value.type)

    def __repr__(self):
        return "%s (%s)" % (self.field, self.type)
