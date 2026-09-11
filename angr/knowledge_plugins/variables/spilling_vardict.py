from __future__ import annotations

import collections.abc
import logging
import os
from collections import OrderedDict
from typing import TYPE_CHECKING

from angr.utils.lmdb import lmdb, lmdb_available

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .variable_manager import DecompilationVariableManager, VariableManagerInternal

l = logging.getLogger(name=__name__)

# The default number of per-function decompilation variable managers to keep in memory when spilling is enabled.
DECVARS_CACHE_LIMIT = 1000
USE_SPILLING_DVARS = lmdb_available and os.environ.get("USE_SPILLING_DVARS", "True").lower() not in (
    "0",
    "false",
    "no",
)


class SpillingVariableInternalDict(collections.abc.MutableMapping):
    """
    A dict of per-function VariableManagerInternal instances (keyed by function address) that keeps only the most
    recently used cache_limit entries in memory and spills the rest to an LMDB database managed by the RuntimeDb
    knowledge base plugin. It is the backing store for ``DecompilationVariableManager.function_managers``.

    Evicted entries are serialized and written out; they are deserialized on access with the owning manager
    reattached. Decompilation only mutates a function's internal manager while decompiling that function (when it is
    the most-recently-used entry) and treats it as read-only afterwards, so spilling is safe.

    On pickle, the serialized entries travel inside the pickle and are re-imported into a fresh LMDB on first access
    after unpickling.
    """

    def __init__(self, manager: DecompilationVariableManager, cache_limit: int = DECVARS_CACHE_LIMIT):
        self._manager = manager
        self._cache_limit: int = cache_limit
        self._cache: OrderedDict[int, VariableManagerInternal] = OrderedDict()  # LRU order: oldest first
        self._spilled: set[int] = set()
        self._db: str | None = None
        self._eviction_enabled: bool = True
        # serialized entries restored by __setstate__, imported into LMDB on first access (the owning knowledge
        # base may still be mid-unpickle during __setstate__)
        self._pending_import: dict[int, bytes] | None = None

    @property
    def cache_limit(self) -> int:
        return self._cache_limit

    #
    # LMDB management
    #

    @property
    def _kb(self):
        return self._manager._kb  # pylint: disable=protected-access

    def _init_lmdb(self) -> None:
        if self._db is None:
            self._db = self._kb.rtdb.open_db("dvars")

    @staticmethod
    def _lmdb_key(key: int) -> bytes:
        return str(key).encode()

    def _bulk_put(self, items: list[tuple[int, bytes]]) -> None:
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

    def _save_to_lmdb(self, key: int, blob: bytes) -> None:
        self._flush_pending()
        self._bulk_put([(key, blob)])

    def _load_from_lmdb(self, key: int) -> VariableManagerInternal:

        from .variable_manager import VariableManagerInternal  # pylint:disable=import-outside-toplevel

        self._flush_pending()

        assert self._db is not None
        with self._kb.rtdb.begin_txn(self._db) as txn:
            blob = txn.get(self._lmdb_key(key))
        if blob is None:
            raise KeyError(key)
        internal = VariableManagerInternal.parse(blob, variable_manager=self._manager, func_addr=key)
        internal.set_manager(self._manager)
        self._spilled.discard(key)
        self[key] = internal
        return internal

    #
    # Eviction
    #

    def _evict_lru(self) -> None:
        while self._eviction_enabled and len(self._cache) > self._cache_limit:
            key, internal = self._cache.popitem(last=False)
            blob = internal.serialize()
            self._save_to_lmdb(key, blob)
            self._spilled.add(key)

    #
    # MutableMapping interface
    #

    def __getitem__(self, key: int) -> VariableManagerInternal:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        if key in self._spilled:
            return self._load_from_lmdb(key)
        raise KeyError(key)

    def __setitem__(self, key: int, value: VariableManagerInternal) -> None:
        self._spilled.discard(key)
        self._cache[key] = value
        self._cache.move_to_end(key)
        self._evict_lru()

    def __delitem__(self, key: int) -> None:
        if key in self._cache:
            del self._cache[key]
        elif key in self._spilled:
            # don't bother deleting the LMDB record; the key is simply forgotten
            self._spilled.discard(key)
        else:
            raise KeyError(key)

    def __contains__(self, key) -> bool:
        return key in self._cache or key in self._spilled

    def __len__(self) -> int:
        return len(self._cache) + len(self._spilled)

    def __iter__(self) -> Iterator[int]:
        # snapshot the keys: consumers that call __getitem__ per key (e.g. items()/values()) mutate the live
        # containers mid-iteration
        yield from list(self._cache)
        yield from list(self._spilled)

    #
    # Pickling
    #
    # Live entries are serialized to their protobuf bytes and spilled entries are copied straight out of LMDB, so
    # the pickle is self-contained and does not reference the (non-durable) RuntimeDb.
    #

    def __getstate__(self) -> dict:
        self._flush_pending()
        serialized: dict[int, bytes] = {key: internal.serialize() for key, internal in self._cache.items()}
        if self._spilled:
            assert self._db is not None
            with self._kb.rtdb.begin_txn(self._db) as txn:
                for key in self._spilled:
                    blob = txn.get(self._lmdb_key(key))
                    if blob is not None:
                        serialized[key] = blob
        return {"manager": self._manager, "cache_limit": self._cache_limit, "serialized": serialized}

    def __setstate__(self, state: dict) -> None:
        self.__init__(state["manager"], cache_limit=state["cache_limit"])  # type: ignore[misc]
        # defer the LMDB import to the first real access; the knowledge base may still be mid-unpickle here
        self._pending_import = dict(state["serialized"])
        self._spilled = set(self._pending_import)
