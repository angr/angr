from __future__ import annotations
from . import translate_value
from .base import SimSootValue
from ..field_dispatcher import resolve_field


class SimSootValue_InstanceFieldRef(SimSootValue):
    __slots__ = ["id", "class_name", "field_name", "type"]

    def __init__(self, heap_alloc_id, class_name, field_name, type_):
        self.id = f"{heap_alloc_id}.{class_name}.{field_name}"
        self.class_name = class_name
        self.field_name = field_name
        self.type = type_

    def __repr__(self):
        return self.id

    @classmethod
    def from_field_id(cls, heap_alloc_id, field_id):
        return cls(heap_alloc_id, field_id.class_name, field_id.name, field_id.type)

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        field_name, field_class_name = soot_value.field
        field_type = soot_value.type
        # get heap allocation id from base object
        fixed_base = translate_value(soot_value.base, state)
        field_ref_base = state.memory.load(fixed_base)
        obj_alloc_id = field_ref_base.heap_alloc_id
        # return field reference
        return cls.get_ref(state, obj_alloc_id, field_class_name, field_name, field_type)

    @classmethod
    def get_ref(cls, state, obj_alloc_id, field_class_name, field_name, field_type):
        """
        Resolve the field within the given state.
        """
        # resolve field
        field_class = state.javavm_classloader.get_class(field_class_name)
        field_id = resolve_field(state, field_class, field_name, field_type)
        # return field ref
        return cls.from_field_id(obj_alloc_id, field_id)
