from .base import SimSootValue
from ..field_dispatcher import resolve_field


class SimSootValue_StaticFieldRef(SimSootValue):
    __slots__ = ["id", "class_name", "field_name", "type"]

    def __init__(self, class_name, field_name, type_):
        self.id = f"{class_name}.{field_name}"
        self.class_name = class_name
        self.field_name = field_name
        self.type = type_

    def __repr__(self):
        return self.id

    @classmethod
    def from_field_id(cls, field_id):
        return cls(field_id.class_name, field_id.name, field_id.type)

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        field_name, field_class_name = soot_value.field
        field_type = soot_value.type
        # return field reference
        return cls.get_ref(state, field_class_name, field_name, field_type)

    @classmethod
    def get_ref(cls, state, field_class_name, field_name, field_type):
        """
        Resolve the field within the given state.
        """
        # resolve field
        field_class = state.javavm_classloader.get_class(field_class_name)
        field_id = resolve_field(state, field_class, field_name, field_type)
        # return field ref
        return cls.from_field_id(field_id)
