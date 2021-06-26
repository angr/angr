from collections import UserDict

from .plugin import KnowledgeBasePlugin
from ..sim_type import ALL_TYPES

class TypesStore(KnowledgeBasePlugin, UserDict):
    """
    A kb plugin that stores a mapping from name to SimType. It will return types from angr.sim_type.ALL_TYPES as
    a default.
    """
    def __init__(self, kb):
        super().__init__()
        self.kb = kb

    def copy(self):
        o = TypesStore(self.kb)
        o.update(self)
        return o

    def __getitem__(self, item):
        try:
            return super().__getitem__(item)
        except KeyError:
            return ALL_TYPES[item]

    def __iter__(self):
        yield from super().__iter__()
        yield from iter(ALL_TYPES)

KnowledgeBasePlugin.register_default('types', TypesStore)
