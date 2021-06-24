from collections import UserDict

from .plugin import KnowledgeBasePlugin
from ..sim_type import ALL_TYPES

class TypesStore(KnowledgeBasePlugin, UserDict):
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
