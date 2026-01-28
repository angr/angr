from __future__ import annotations

from collections.abc import Callable

from cachetools import LRUCache


class SmartLRUCache(LRUCache):
    """
    An LRU cache that supports an eviction callback.
    """

    def __init__(self, maxsize, getsizeof=None, evict: Callable | None = None):
        LRUCache.__init__(self, maxsize, getsizeof=getsizeof)
        self._evict = evict

    def popitem(self):
        key, val = LRUCache.popitem(self)
        if self._evict is not None:
            self._evict(key, val)
        return key, val
