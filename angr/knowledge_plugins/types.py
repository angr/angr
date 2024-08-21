import random
from collections import UserDict

from .plugin import KnowledgeBasePlugin
from ..sim_type import ALL_TYPES, TypeRef


FRUITS = [
    "mango",
    "cherry",
    "banana",
    "papaya",
    "apple",
    "kiwi",
    "pineapple",
    "coconut",
    "peach",
    "honeydew",
    "cucumber",
    "pumpkin",
    "cantaloupe",
    "strawberry",
    "watermelon",
    "nectarine",
    "orange",
]


class TypesStore(KnowledgeBasePlugin, UserDict):
    """
    A kb plugin that stores a mapping from name to TypeRef. It will return types from angr.sim_type.ALL_TYPES as
    a default.
    """

    def __init__(self, kb):
        super().__init__(kb=kb)

    def copy(self):
        o = TypesStore(self._kb)
        o.update(super().items())
        return o

    def __getitem__(self, item):
        try:
            return super().__getitem__(item)
        except KeyError:
            return ALL_TYPES[item]

    def __setitem__(self, item, value):
        if type(value) is not TypeRef:
            raise TypeError("Can only store TypeRefs in TypesStore")

        super().__setitem__(item, value.with_arch(self._kb._project.arch))

    def __iter__(self):
        yield from super().__iter__()
        yield from iter(ALL_TYPES)

    def __getstate__(self):
        return self.data  # do not pickle self.kb

    def __setstate__(self, state):
        self.data = state

    def iter_own(self):
        """
        Iterate over all the names which are stored in this object - i.e. ``values()`` without ``ALL_TYPES``
        """
        for key in super().__iter__():
            yield self[key]

    def rename(self, old, new):
        value = self.pop(old)
        value._name = new
        self[new] = value

    def unique_type_name(self) -> str:
        for fruit in FRUITS:
            if fruit not in self:
                name = fruit
                break
        else:
            name = f"type_{random.randint(0x10000000, 0x100000000):x}"
        return name


KnowledgeBasePlugin.register_default("types", TypesStore)
