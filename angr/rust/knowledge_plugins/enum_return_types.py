from __future__ import annotations
from angr.knowledge_plugins import KnowledgeBasePlugin


class EnumReturnTypes(KnowledgeBasePlugin):
    """Store inferred enum return types for functions."""

    def __init__(self, kb):
        super().__init__(kb)
        self.enum_return_types = {}

    def __iter__(self):
        return iter(self.enum_return_types)

    def __setitem__(self, key, value):
        self.enum_return_types[key] = value

    def __getitem__(self, item):
        return self.enum_return_types.get(item, None)

    def __contains__(self, item):
        return item in self.enum_return_types


KnowledgeBasePlugin.register_default("enum_return_types", EnumReturnTypes)
