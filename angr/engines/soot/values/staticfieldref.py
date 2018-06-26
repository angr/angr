
from .base import SimSootValue

import logging
l = logging.getLogger('angr.engines.soot.values.staticfieldref')

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
        field_name, field_class_name = soot_value.field
        field_type = soot_value.type
        # applications can access static fields before the class was initialized
        # => if the class hasn't been initialized yet, we need to initialize it
        field_class = state.javavm_classloader.get_class(field_class_name, init_class=True)
        if field_class is None:
            l.warning("Trying to access static field {field} from an unloaded class {class_name}"
                      "".format(field=cls._create_unique_id(field_name, field_class), 
                                class_name=field_class_name))
        # return field ref
        return cls(field_class_name, field_name, field_type)

    def __repr__(self):
        return self.id
