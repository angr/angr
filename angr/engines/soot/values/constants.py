from .base import SimSootValue

class SimSootValue_IntConstant(SimSootValue):

    __slots__ = [ 'value', 'type' ]

    def __init__(self, value, type_):
        super(SimSootValue_IntConstant, self).__init__()
        self.value = value
        self.type = type_

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        return cls(soot_value.value, soot_value.type)

    def __repr__(self):
        return self.value

class SimSootValue_ClassConstant(SimSootValue):

    __slots__ = [ 'value', 'type' ]

    def __init__(self, value, type_):
        super(SimSootValue_ClassConstant, self).__init__()
        self.value = value
        self.type = type_

    @property
    def class_name(self):
        return self.value[8:-2]

    @classmethod
    def from_sootvalue(cls, soot_value):
        return cls(soot_value.value, soot_value.type)

    @classmethod
    def from_classname(cls, fully_qualified_cls_name):
        class_descriptor = 'class "L{cls_name};"'.format(cls_name=fully_qualified_cls_name)
        return cls(value=class_descriptor, type_='java.lang.Class')


    def __repr__(self):
        return self.value