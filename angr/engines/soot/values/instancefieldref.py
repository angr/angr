
from . import translate_value
from .base import SimSootValue


class SimSootValue_InstanceFieldRef(SimSootValue):

    __slots__ = ['id', 'class_name', 'field_name', 'type']

    def __init__(self, heap_alloc_id, class_name, field_name, type_):
        self.id = "%s.%s.%s" % (heap_alloc_id, class_name, field_name)
        self.class_name = class_name
        self.field_name = field_name
        self.type = type_

    def __repr__(self):
        return self.id

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        field_name, field_class_name = soot_value.field
        field_type = soot_value.type
        # get heap allocation id from base object
        fixed_base = translate_value(soot_value.base, state)
        field_ref_base = state.memory.load(fixed_base)
        heap_alloc_id = field_ref_base.heap_alloc_id
        return cls(heap_alloc_id, field_class_name, field_name, field_type)
