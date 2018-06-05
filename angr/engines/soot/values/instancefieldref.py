
from .base import SimSootValue
from . import translate_value


class SimSootValue_InstanceFieldRef(SimSootValue):

    __slots__ = ['id', 'type', 'class_name', 'field_name', 'heap_alloc_id']

    def __init__(self, heap_alloc_id, class_name, field_name, type_):
        self.id = self._create_unique_id(heap_alloc_id, class_name, field_name)
        self.heap_alloc_id = heap_alloc_id
        self.class_name = class_name
        self.field_name = field_name
        self.type = type_

    @staticmethod
    def _create_unique_id(heap_alloc_id, class_name, field_name):
        return "%s.%s.%s" % (heap_alloc_id, class_name, field_name)

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        fixed_base = translate_value(soot_value.base, state)
        field_ref_base = state.memory.load(fixed_base)
        return cls(field_ref_base.heap_alloc_id, soot_value.field[1], soot_value.field[0], soot_value.type)

    def __repr__(self):
        return self.id
