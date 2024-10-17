# pylint:disable=import-outside-toplevel
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from angr.analyses.decompiler.decompilation_cache import DecompilationCache


class DecompilationManager(KnowledgeBasePlugin):
    """A knowledge base plugin to store decompilation results."""

    def __init__(self, kb):
        super().__init__(kb=kb)
        self.cached: dict[Any, DecompilationCache] = {}

    def _normalize_key(self, item: int | str):
        if type(item) is str:
            item = (self._kb.labels.lookup(item[0]), *item[1:])
        return item

    def __getitem__(self, item) -> DecompilationCache:
        return self.cached[self._normalize_key(item)]

    def __setitem__(self, key, value: DecompilationCache):
        self.cached[self._normalize_key(key)] = value

    def __contains__(self, key):
        return self._normalize_key(key) in self.cached

    def __delitem__(self, key):
        del self.cached[self._normalize_key(key)]

    def discard(self, key):
        normalized_key = self._normalize_key(key)
        if normalized_key in self.cached:
            del self.cached[normalized_key]

    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default("decompilations", DecompilationManager)
