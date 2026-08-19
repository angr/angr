"""
A generic SortedDict-compatible, dict-like container with LRU caching and LMDB spilling.

This mirrors the spilling infrastructure used for CFG nodes/edges and functions
(:class:`~angr.knowledge_plugins.cfg.spilling_cfg.SpillingCFGNodeDict`,
:class:`~angr.knowledge_plugins.functions.function_manager.SpillingFunctionDict`), but is meant for
address-keyed auxiliary structures such as ``CFGModel.memory_data`` and the ``XRefManager`` indexes.

Unlike those containers, :class:`SpillingObjectDict` does **not** rely on a per-value ``dirty`` flag.
Its values are commonly mutated in place through references handed out by ``__getitem__`` (a
``MemoryData`` object during ``tidy_data_references``, or a ``set`` of ``XRef`` during ``add_xref``) and
are not written back. Detecting such mutations cheaply is not possible, so every evicted entry is
serialized unconditionally. Because callers always finish mutating an entry before touching sibling
keys (which is what can trigger the entry's eviction), the entry's on-disk copy always reflects its
latest completed mutation -- which is exactly what byte-identical output depends on.
"""

from __future__ import annotations

import logging
import pickle
import threading
import weakref
from collections import OrderedDict
from collections.abc import Iterator
from typing import TYPE_CHECKING

import lmdb
from sortedcontainers import SortedList

if TYPE_CHECKING:
    from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb

l = logging.getLogger(name=__name__)

_missing = object()


class SpillingObjectDict[K, V]:
    """
    A dict-like container that keeps only the most recently accessed ``cache_limit`` entries in memory,
    spilling the rest to an LMDB database on disk. Keys are kept in sorted order, so the container also
    supports the ``SortedDict`` query methods (``irange``, ``islice``, ``bisect_left``, ``bisect_right``)
    that ``CFGModel.memory_data`` and the xref indexes rely on.

    Subclasses customize value (de)serialization by overriding :meth:`_serialize_value` and
    :meth:`_deserialize_value` (the default is :mod:`pickle`), and may enable ``defaultdict``-style
    auto-vivification by setting :attr:`_VIVIFY` and overriding :meth:`_make_default`.

    :ivar rtdb:                 The :class:`RuntimeDb` used for LMDB access. ``None`` disables spilling.
    :ivar cache_limit:          The maximum number of entries to keep in memory, or ``None`` to never spill.
    :ivar _lru_order:           An OrderedDict tracking the eviction order of cached entries.
    :ivar _spilled_keys:        The set of keys currently spilled to LMDB.
    :ivar _list:                A SortedList of all keys (cached + spilled).
    :ivar _db_batch_size:       How many entries are evicted in a single batch.
    """

    # LMDB base name used to open the backing database. Subclasses must override.
    _DB_NAME: str = "spilling_objects"
    # Whether ``__getitem__`` on a missing key auto-creates (and stores) a default value.
    _VIVIFY: bool = False
    # Whether keys are kept in sorted order (enabling irange/islice/bisect and sorted iteration). Set False to
    # preserve insertion order instead (e.g. to match networkx's plain-dict adjacency iteration order).
    _SORTED: bool = True
    # Whether to guarantee canonical object identity: a value handed out for a key is always the *same*
    # Python object while it is still referenced anywhere (e.g. through insn_addr_to_memory_data or an XRef).
    # Reloading from LMDB reuses the live object instead of deserializing a divergent copy. Values must be
    # weakly referenceable. This is required whenever an evicted value can still be mutated (or read) through
    # a reference held outside this container.
    _CANONICAL_IDENTITY: bool = False

    def __init__(
        self,
        rtdb: RuntimeDb | None,
        cache_limit: int | None = None,
        db_batch_size: int = 200,
    ):
        self.rtdb: RuntimeDb | None = rtdb
        self._cache_limit: int | None = cache_limit
        self._db_batch_size: int = db_batch_size

        self._data: dict[K, V] = {}
        self._spilled_keys: set[K] = set()
        self._lru_order: OrderedDict[K, None] = OrderedDict()
        # registry of all keys (cached + spilled): a SortedList when _SORTED (for irange/islice/bisect), else an
        # insertion-ordered dict (keys map to None) to mirror networkx's plain-dict adjacency iteration order.
        self._list = SortedList() if self._SORTED else {}
        # canonical-object registry: keeps a weak reference to every value handed out, so that a value which
        # is still referenced elsewhere is never replaced by a divergent copy reloaded from LMDB.
        self._canonical: weakref.WeakValueDictionary[K, V] | None = (
            weakref.WeakValueDictionary() if self._CANONICAL_IDENTITY else None
        )

        self._db: str | None = None
        self._eviction_enabled: bool = True
        self._loading_from_lmdb: bool = False
        self._db_load_lock = threading.Lock()
        self._db_store_lock = threading.Lock()

    def __del__(self):
        self._cleanup_lmdb()

    def _key_add(self, key: K) -> None:
        if self._SORTED:
            self._list.add(key)
        else:
            self._list[key] = None

    def _key_remove(self, key: K) -> None:
        if self._SORTED:
            self._list.remove(key)
        else:
            del self._list[key]

    #
    # Value (de)serialization -- override in subclasses
    #

    def _serialize_value(self, value: V) -> bytes:
        return pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)

    def _deserialize_value(self, data: bytes) -> V:
        return pickle.loads(data)

    def _make_default(self) -> V:
        raise KeyError

    #
    # Mapping interface
    #

    def __getitem__(self, key: K) -> V:
        if key in self._data:
            self._touch(key)
            return self._data[key]

        if key in self._spilled_keys:
            value = self._load_from_lmdb(key)
            if value is not _missing:
                return value  # type: ignore[return-value]

        if self._VIVIFY:
            value = self._make_default()
            self[key] = value
            return value

        raise KeyError(key)

    def __setitem__(self, key: K, value: V) -> None:
        if key not in self._data and key not in self._spilled_keys:
            self._key_add(key)
        self._data[key] = value
        if self._canonical is not None:
            self._canonical[key] = value
        self._on_stored(key)

    def __delitem__(self, key: K) -> None:
        present = key in self._data or key in self._spilled_keys
        if key in self._data:
            del self._data[key]
        self._spilled_keys.discard(key)
        if key in self._lru_order:
            del self._lru_order[key]
        if self._canonical is not None:
            self._canonical.pop(key, None)
        if present:
            self._key_remove(key)

    def __contains__(self, key: object) -> bool:
        return key in self._data or key in self._spilled_keys

    def __len__(self) -> int:
        return len(self._data) + len(self._spilled_keys)

    def __iter__(self) -> Iterator[K]:
        yield from self._list

    def __bool__(self) -> bool:
        return len(self._list) > 0

    def get(self, key: K, default=None):
        if key in self._data:
            self._touch(key)
            return self._data[key]
        if key in self._spilled_keys:
            value = self._load_from_lmdb(key)
            if value is not _missing:
                return value
        return default

    def setdefault(self, key: K, default: V) -> V:
        if key in self:
            return self[key]
        self[key] = default
        return default

    def keys(self) -> list[K]:
        return list(self._list)

    def values(self) -> Iterator[V]:
        for key in list(self._list):
            yield self[key]

    def items(self) -> Iterator[tuple[K, V]]:
        for key in list(self._list):
            yield key, self[key]

    def pop(self, key: K, default=_missing):
        try:
            value = self[key]
        except KeyError:
            if default is _missing:
                raise
            return default
        del self[key]
        return value

    def clear(self) -> None:
        self._data.clear()
        self._lru_order.clear()
        self._spilled_keys.clear()
        self._list.clear()
        if self._canonical is not None:
            self._canonical.clear()
        self._cleanup_lmdb()

    #
    # SortedDict-compatible query methods (backed by the sorted key list)
    #

    def irange(self, minimum=None, maximum=None, inclusive=(True, True), reverse=False):
        return self._list.irange(minimum, maximum, inclusive=inclusive, reverse=reverse)

    def islice(self, start=None, stop=None, reverse=False):
        return self._list.islice(start, stop, reverse=reverse)

    def bisect_left(self, value):
        return self._list.bisect_left(value)

    def bisect_right(self, value):
        return self._list.bisect_right(value)

    #
    # Properties
    #

    @property
    def cache_limit(self) -> int | None:
        return self._cache_limit

    @cache_limit.setter
    def cache_limit(self, value: int | None) -> None:
        self._cache_limit = value
        if value is not None and len(self._data) > value + self._db_batch_size:
            self._evict_lru()

    @property
    def db_batch_size(self) -> int:
        return self._db_batch_size

    @property
    def cached_count(self) -> int:
        return len(self._data)

    @property
    def spilled_count(self) -> int:
        return len(self._spilled_keys)

    @property
    def total_count(self) -> int:
        return len(self._data) + len(self._spilled_keys)

    def is_cached(self, key: K) -> bool:
        return key in self._data

    #
    # LRU cache management
    #

    def _touch(self, key: K) -> None:
        if key in self._lru_order:
            self._lru_order.move_to_end(key)
        else:
            self._lru_order[key] = None

    def _on_stored(self, key: K) -> None:
        self._touch(key)
        self._spilled_keys.discard(key)
        if (
            self._eviction_enabled
            and self._cache_limit is not None
            and len(self._data) > self._cache_limit + self._db_batch_size
        ):
            self._evict_lru()

    def _evict_lru(self) -> bool:
        with self._db_store_lock:
            evicted_any = False
            while self._cache_limit is not None and len(self._data) > self._cache_limit + self._db_batch_size:
                to_evict = len(self._data) - self._cache_limit
                batch_size = min(self._db_batch_size, to_evict)
                if self._evict_n(batch_size) == 0:
                    break
                evicted_any = True
            return evicted_any

    def _evict_n(self, n: int) -> int:
        if self.rtdb is None:
            # Without a RuntimeDb we cannot persist evicted entries; evicting anyway would silently lose data
            # (this happens e.g. while unpickling, before an rtdb is re-attached).
            return 0
        if not self._lru_order:
            return 0

        evicted = 0
        to_save: list[tuple[K, V]] = []
        keys_to_remove: list[K] = []
        for lru_key in self._lru_order:
            if evicted >= n:
                break
            if lru_key not in self._data:
                keys_to_remove.append(lru_key)
                continue
            # Always serialize -- values may have been mutated in place since they were stored/loaded.
            to_save.append((lru_key, self._data[lru_key]))
            del self._data[lru_key]
            keys_to_remove.append(lru_key)
            self._spilled_keys.add(lru_key)
            evicted += 1

        for lru_key in keys_to_remove:
            del self._lru_order[lru_key]

        if to_save:
            self._save_to_lmdb(to_save)

        return evicted

    #
    # LMDB management
    #

    def _init_lmdb(self) -> None:
        if self._db is None and self.rtdb is not None:
            self._db = self.rtdb.open_db(self._DB_NAME)

    def _cleanup_lmdb(self) -> None:
        if self._db is not None and self.rtdb is not None:
            self.rtdb.drop_db(self._db)
            self._db = None

    @staticmethod
    def _encode_key(key: K) -> bytes:
        return str(key).encode("utf-8")

    def _save_to_lmdb(self, items: list[tuple[K, V]]) -> None:
        if self.rtdb is None:
            return
        self._init_lmdb()
        assert self._db is not None

        while True:
            try:
                with self.rtdb.begin_txn(self._db, write=True) as txn:
                    for key, value in items:
                        txn.put(self._encode_key(key), self._serialize_value(value))
                break
            except lmdb.MapFullError:
                self.rtdb.increase_lmdb_map_size()

    def _load_from_lmdb(self, key: K):
        if self._db is None or self.rtdb is None:
            return _missing
        with self._db_load_lock:
            return self._load_from_lmdb_core(key)

    def _load_from_lmdb_core(self, key: K):
        if self._loading_from_lmdb:
            raise RuntimeError("Recursive loading from LMDB detected. This is a bug.")
        assert self.rtdb is not None and self._db is not None

        self._loading_from_lmdb = True
        try:
            # If a live object for this key still exists anywhere (e.g. held by insn_addr_to_memory_data or an
            # XRef), reuse it instead of deserializing a divergent copy. The live object is authoritative: it
            # may carry in-place mutations made after the LMDB record was written.
            if self._canonical is not None:
                live = self._canonical.get(key)
                if live is not None:
                    self._spilled_keys.discard(key)
                    self._data[key] = live
                    self._on_stored(key)
                    return live

            with self.rtdb.begin_txn(self._db) as txn:
                raw = txn.get(self._encode_key(key))
                if raw is None:
                    return _missing
                value = self._deserialize_value(raw)

            self._spilled_keys.discard(key)
            self._data[key] = value
            if self._canonical is not None:
                self._canonical[key] = value
            self._on_stored(key)
            return value
        finally:
            self._loading_from_lmdb = False
            if (
                self._eviction_enabled
                and self._cache_limit is not None
                and len(self._data) > self._cache_limit + self._db_batch_size
            ):
                self._evict_lru()

    def load_all_spilled(self) -> None:
        if not self._spilled_keys:
            return
        old_state = self._eviction_enabled
        self._eviction_enabled = False
        try:
            for key in list(self._spilled_keys):
                self._load_from_lmdb(key)
        finally:
            self._eviction_enabled = old_state

    def evict_all_cached(self) -> None:
        if not self._data:
            return
        with self._db_store_lock:
            self._evict_n(len(self._data))

    def set_rtdb(self, rtdb: RuntimeDb | None) -> None:
        """(Re-)attach a RuntimeDb (e.g. after unpickling)."""
        self.rtdb = rtdb

    #
    # Copy / pickling
    #

    def _new_like(self) -> SpillingObjectDict[K, V]:
        """Construct an empty container with the same configuration. Subclasses with extra state override."""
        return type(self)(self.rtdb, cache_limit=self._cache_limit, db_batch_size=self._db_batch_size)

    def copy(self) -> SpillingObjectDict[K, V]:
        new = self._new_like()
        new._eviction_enabled = False
        # Share cached value objects (shallow, matching SortedDict.copy semantics).
        for key in self._data:
            new._data[key] = self._data[key]
            if new._canonical is not None:
                new._canonical[key] = self._data[key]
            new._lru_order[key] = None
            new._key_add(key)
        # Byte-copy spilled records.
        if self._spilled_keys and self._db is not None and self.rtdb is not None:
            new._init_lmdb()
            assert new._db is not None
            with (
                self.rtdb.begin_txn(self._db) as src_txn,
                self.rtdb.begin_txn(new._db, write=True) as dst_txn,
            ):
                for key in self._spilled_keys:
                    raw = src_txn.get(self._encode_key(key))
                    if raw is not None:
                        dst_txn.put(self._encode_key(key), raw)
                        new._spilled_keys.add(key)
                        new._key_add(key)
        new._eviction_enabled = True
        return new

    def _pickle_extra_state(self) -> dict:
        """Extra per-subclass state to preserve across pickling."""
        return {}

    def _restore_extra_state(self, state: dict) -> None:
        pass

    def __getstate__(self) -> dict:
        # Materialize everything so no data is lost through pickling.
        self.load_all_spilled()
        return {
            "cache_limit": self._cache_limit,
            "db_batch_size": self._db_batch_size,
            "items": dict(self._data),
            "extra": self._pickle_extra_state(),
        }

    def __setstate__(self, state: dict) -> None:
        self._cache_limit = state["cache_limit"]
        self._db_batch_size = state["db_batch_size"]
        self.rtdb = None
        self._data = {}
        self._spilled_keys = set()
        self._lru_order = OrderedDict()
        self._list = SortedList() if self._SORTED else {}
        self._canonical = weakref.WeakValueDictionary() if self._CANONICAL_IDENTITY else None
        self._db = None
        self._eviction_enabled = True
        self._loading_from_lmdb = False
        self._db_load_lock = threading.Lock()
        self._db_store_lock = threading.Lock()
        self._restore_extra_state(state.get("extra", {}))
        for key, value in state["items"].items():
            self[key] = value
