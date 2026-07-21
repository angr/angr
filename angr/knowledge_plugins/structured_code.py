# pylint:disable=import-outside-toplevel
from __future__ import annotations

import collections.abc
import logging
import os
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

import lmdb

import angr

from .plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from collections.abc import Iterator, MutableMapping

    from angr.analyses.decompiler.decompilation_cache import DecompilationCache
    from angr.analyses.decompiler.structured_codegen import BaseStructuredCodeGenerator
    from angr.knowledge_base import KnowledgeBase

l = logging.getLogger(name=__name__)

# The default number of decompilation caches to keep in memory when spilling is enabled.
DECOMPILATION_CACHE_LIMIT = 128
USE_SPILLING_CODE_CACHE = os.environ.get("USE_SPILLING_CODE_CACHE", "True").lower() not in ("0", "false", "no")

# (function address, flavor)
CacheKey = tuple[int, str]


class SpillingDecompilationDict(collections.abc.MutableMapping):
    """
    A dict of decompilation caches, keyed by (function address, flavor), that keeps only the most recently used
    cache_limit entries in memory and spills the rest to an LMDB database managed by the RuntimeDb knowledge base
    plugin.

    Evicted entries are always serialized and written out (decompilation caches are mutated in place, e.g. via
    ``errors`` and codegen comments, so there is no reliable clean/dirty distinction). Entries that cannot be
    serialized (e.g. caches holding a DummyStructuredCodeGenerator or a rust-flavor codegen) are parked in an
    unbounded in-memory dict and behave as if spilling were disabled.

    Spilled entries are deserialized on access with the owning knowledge base's project/function attached. Like all
    deserialized decompilation caches, they come back without the four typehoon slots and without ``cfg``, which
    cache-validity checks treat as valid.
    """

    def __init__(self, kb: KnowledgeBase, cache_limit: int = DECOMPILATION_CACHE_LIMIT):
        self._kb = kb
        self._cache_limit: int = cache_limit
        self._cache: OrderedDict[CacheKey, DecompilationCache] = OrderedDict()  # LRU order: oldest first
        self._spilled: set[CacheKey] = set()
        self._unspillable: dict[CacheKey, DecompilationCache] = {}
        self._db: str | None = None
        self._eviction_enabled: bool = True
        self._warned_unspillable: bool = False
        # serialized entries restored by __setstate__ that have not been written to LMDB yet; unpickling cannot touch
        # the RuntimeDb plugin because the owning knowledge base may itself still be mid-unpickle
        self._pending_import: dict[CacheKey, bytes] | None = None

    #
    # LMDB management
    #

    @property
    def cache_limit(self) -> int:
        return self._cache_limit

    def _init_lmdb(self) -> None:
        if self._db is None:
            self._db = self._kb.rtdb.open_db("decompilations")

    @staticmethod
    def _lmdb_key(key: CacheKey) -> bytes:
        addr, flavor = key
        return f"{addr}:{flavor}".encode()

    def _bulk_put(self, items: list[tuple[CacheKey, bytes]]) -> None:
        self._init_lmdb()
        assert self._db is not None
        while True:
            try:
                with self._kb.rtdb.begin_txn(self._db, write=True) as txn:
                    for key, blob in items:
                        txn.put(self._lmdb_key(key), blob)
                break
            except lmdb.MapFullError:
                self._kb.rtdb.increase_lmdb_map_size()

    def _flush_pending(self) -> None:
        if self._pending_import:
            items = list(self._pending_import.items())
            self._pending_import = None
            self._bulk_put(items)
        else:
            self._pending_import = None

    def _save_to_lmdb(self, key: CacheKey, blob: bytes) -> None:
        self._flush_pending()
        self._bulk_put([(key, blob)])

    def _load_from_lmdb(self, key: CacheKey) -> DecompilationCache:
        self._flush_pending()
        from angr.analyses.decompiler.decompilation_cache import DecompilationCache

        assert self._db is not None
        with self._kb.rtdb.begin_txn(self._db) as txn:
            blob = txn.get(self._lmdb_key(key))
        if blob is None:
            raise KeyError(key)
        addr, _flavor = key
        cache = DecompilationCache.parse(
            blob,
            project=self._kb._project,
            kb=self._kb,
            function=self._kb.functions.get(addr),
        )
        self._spilled.discard(key)
        self[key] = cache
        return cache

    #
    # Eviction
    #

    def _evict_lru(self) -> None:
        while self._eviction_enabled and len(self._cache) > self._cache_limit:
            key, cache = self._cache.popitem(last=False)
            try:
                blob = cache.serialize()
            except Exception:  # pylint:disable=broad-exception-caught
                if not self._warned_unspillable:
                    self._warned_unspillable = True
                    l.warning(
                        "Decompilation cache %r cannot be serialized and will be kept in memory. Further "
                        "occurrences will not be logged.",
                        key,
                        exc_info=True,
                    )
                self._unspillable[key] = cache
                continue
            self._save_to_lmdb(key, blob)
            self._spilled.add(key)

    #
    # MutableMapping interface
    #

    def __getitem__(self, key: CacheKey) -> DecompilationCache:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        if key in self._unspillable:
            return self._unspillable[key]
        if key in self._spilled:
            return self._load_from_lmdb(key)
        raise KeyError(key)

    def __setitem__(self, key: CacheKey, value: DecompilationCache) -> None:
        self._spilled.discard(key)
        self._unspillable.pop(key, None)
        self._cache[key] = value
        self._cache.move_to_end(key)
        self._evict_lru()

    def __delitem__(self, key: CacheKey) -> None:
        if key in self._cache:
            del self._cache[key]
        elif key in self._unspillable:
            del self._unspillable[key]
        elif key in self._spilled:
            # don't bother deleting the LMDB record; the key is simply forgotten
            self._spilled.discard(key)
        else:
            raise KeyError(key)

    def __contains__(self, key) -> bool:
        return key in self._cache or key in self._unspillable or key in self._spilled

    def __len__(self) -> int:
        return len(self._cache) + len(self._unspillable) + len(self._spilled)

    def __iter__(self) -> Iterator[CacheKey]:
        yield from self._cache
        yield from self._unspillable
        yield from self._spilled

    #
    # Bulk serialized access (for angr databases)
    #

    def export_serialized(self) -> tuple[list[tuple[CacheKey, bytes]], dict[CacheKey, DecompilationCache]]:
        """
        Export all serializable entries as (key, serialized bytes) pairs. Spilled entries are copied directly out of
        the LMDB backing store without being deserialized and re-serialized. Entries that cannot be serialized are
        returned separately in a dict.
        """
        self._flush_pending()
        serialized: list[tuple[CacheKey, bytes]] = []
        unserializable: dict[CacheKey, DecompilationCache] = dict(self._unspillable)

        if self._spilled:
            assert self._db is not None
            with self._kb.rtdb.begin_txn(self._db) as txn:
                for key in self._spilled:
                    blob = txn.get(self._lmdb_key(key))
                    if blob is not None:
                        serialized.append((key, blob))

        for key, cache in self._cache.items():
            try:
                serialized.append((key, cache.serialize()))
            except Exception:  # pylint:disable=broad-exception-caught
                unserializable[key] = cache

        return serialized, unserializable

    def bulk_import_serialized(self, items: list[tuple[CacheKey, bytes]]) -> None:
        """
        Move already-serialized decompilation caches directly into the LMDB backing store and register them as
        spilled, without deserializing them. The bytes must be serialized DecompilationCache messages, i.e., the
        exact format that eviction writes.
        """
        if not items:
            return

        self._flush_pending()
        self._bulk_put(items)

        for key, _ in items:
            # LMDB now holds the authoritative data; drop any stale in-memory copy
            self._cache.pop(key, None)
            self._unspillable.pop(key, None)
            self._spilled.add(key)

    #
    # Pickling
    #
    # Serializable entries are pickled as their protobuf bytes rather than as live Python objects: live caches hold
    # analysis internals (e.g. Typehoon's TypeTranslator) that cannot be pickled. Unserializable entries are pickled
    # as-is, matching the behavior of the plain-dict backing store.
    #

    def __getstate__(self) -> dict:
        serialized, unspillable = self.export_serialized()
        return {
            "kb": self._kb,
            "cache_limit": self._cache_limit,
            "serialized": serialized,
            "unspillable": unspillable,
        }

    def __setstate__(self, state: dict) -> None:
        self.__init__(state["kb"], cache_limit=state["cache_limit"])  # type: ignore[misc]
        # the knowledge base (and its RuntimeDb plugin) may itself still be mid-unpickle; defer the LMDB import to
        # the first real access
        self._pending_import = dict(state["serialized"])
        self._spilled = set(self._pending_import)
        self._unspillable.update(state["unspillable"])


class StructuredCodeManager(KnowledgeBasePlugin):
    """A knowledge base plugin to store structured code generator results."""

    def __init__(self, kb, cache_limit: int | None = None):
        super().__init__(kb=kb)
        if cache_limit is None and USE_SPILLING_CODE_CACHE:
            cache_limit = DECOMPILATION_CACHE_LIMIT
        self.cached: MutableMapping[Any, DecompilationCache] = (
            SpillingDecompilationDict(kb, cache_limit=cache_limit) if cache_limit is not None else {}
        )

    def _normalize_key(self, item):
        if type(item) is not tuple:
            raise TypeError("Structured code can only be queried by tuples of (func, flavor)")
        if type(item[0]) is str:
            item = (self._kb.labels.lookup(item[0]), *item[1:])
        return item

    def __getitem__(self, item) -> DecompilationCache:
        return self.cached[self._normalize_key(item)]

    def __setitem__(self, key, value: DecompilationCache | BaseStructuredCodeGenerator):
        nkey = self._normalize_key(key)

        if isinstance(value, angr.analyses.decompiler.BaseStructuredCodeGenerator):
            cache = angr.analyses.decompiler.DecompilationCache(nkey)
            cache.codegen = value
        else:
            cache = value
        self.cached[nkey] = cache

    def __contains__(self, key):
        return self._normalize_key(key) in self.cached

    def __delitem__(self, key):
        del self.cached[self._normalize_key(key)]

    def get(self, key, default=None):
        return self.cached.get(self._normalize_key(key), default)

    def discard(self, key):
        normalized_key = self._normalize_key(key)
        if normalized_key in self.cached:
            del self.cached[normalized_key]

    def available_flavors(self, item):
        if type(item) is str:
            item = self._kb.labels.lookup(item)
        return [flavor for func, flavor in self.cached if func == item]

    def all_flavors(self, item):  # pylint:disable=no-self-use, unused-argument
        return ["pseudocode", "rust"]

    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default("decompilations", StructuredCodeManager)
