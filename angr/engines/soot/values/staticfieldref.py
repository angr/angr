import logging

from .base import SimSootValue

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
        try:
            # Programs can access static field before class initialization
            # If the class hasn't been loaded yet we need to load it
            class_ = state.project.loader.main_bin.classes[soot_value.field[1]]
            if not state.javavm_classloader.is_class_loaded(class_):
                state.javavm_classloader.load_class(class_)
        except KeyError:
            l.warning("Trying to get a Static Field not loaded (%r)",
                      cls._create_unique_id(soot_value.field[1], soot_value.field[0]))
        return cls(soot_value.field[1], soot_value.field[0], soot_value.type)

    def __repr__(self):
        return self.id
