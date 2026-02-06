from collections.abc import MutableMapping

from angr.knowledge_plugins.plugin import KnowledgeBasePlugin


class RustCallingConventions(KnowledgeBasePlugin, MutableMapping):
    def __init__(self, kb):
        super().__init__(kb)
        self._store = {}

    def __getitem__(self, key):
        return self._store[key]

    def __setitem__(self, key, value):
        self._store[key] = value

    def __delitem__(self, key):
        del self._store[key]

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)

    def __contains__(self, key):
        return key in self._store

    def __repr__(self):
        return f"RustCallingConventions({self._store!r})"

    def copy(self):
        o = RustCallingConventions(self._kb)
        o._store = dict(self._store)
        return o


KnowledgeBasePlugin.register_default("rust_calling_conventions", RustCallingConventions)
