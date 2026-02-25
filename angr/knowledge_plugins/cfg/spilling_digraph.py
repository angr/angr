"""
SpillingDiGraph - a networkx.DiGraph subclass with LMDB-backed edge spilling.

This module provides SpillingAdjDict and SpillingDiGraph classes that implement
disk-backed storage for graph adjacency data, following the SpillingCFGNodeDict pattern.

Edge attributes are serialized using the Edge protobuf message from primitives.proto.
"""

from __future__ import annotations

import ast
import logging
import struct
import threading
from collections import OrderedDict
from collections.abc import Iterator, MutableMapping
from typing import TYPE_CHECKING, Any

import lmdb
import networkx

from angr.protos import primitives_pb2
from angr.utils.enums_conv import cfg_jumpkind_to_pb, cfg_jumpkind_from_pb

if TYPE_CHECKING:
    from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb

l = logging.getLogger(__name__)

# Type alias for block keys used as graph node identifiers
K = Any


class SpillingAdjDict(MutableMapping):
    """
    A dict-like container for adjacency data with LRU caching and LMDB spilling.

    Keys are node keys (block_key tuples), values are inner adjacency dicts
    (mapping neighbor_key -> edge_attr_dict).

    When the number of cached entries exceeds ``cache_limit + db_batch_size``,
    the ``db_batch_size`` least recently used entries are evicted to LMDB.

    Edge attributes within each inner dict are serialized/deserialized using
    the ``Edge`` protobuf message from ``primitives.proto``.
    """

    def __init__(
        self,
        rtdb: RuntimeDb | None = None,
        cache_limit: int = 1000,
        db_batch_size: int = 200,
    ):
        self._data: dict[K, dict[K, dict]] = {}
        self._spilled_keys: set[K] = set()
        self._all_keys: set[K] = set()

        self._cache_limit: int = cache_limit
        self._db_batch_size: int = max(cache_limit - 1, db_batch_size) if cache_limit > 0 else db_batch_size

        self.rtdb: RuntimeDb | None = rtdb

        self._lru_order: OrderedDict[K, None] = OrderedDict()

        self._edgesdb: str | None = None
        self._eviction_enabled: bool = True
        self._loading_from_lmdb: bool = False
        self._db_load_lock = threading.Lock()
        self._db_store_lock = threading.Lock()

    def __del__(self):
        self._cleanup_lmdb()

    #
    #  MutableMapping interface
    #

    def __getitem__(self, key: K) -> dict[K, dict]:
        if key in self._data:
            self._touch(key)
            return self._data[key]

        if key in self._spilled_keys:
            inner_dict = self._load_from_lmdb(key)
            if inner_dict is not None:
                return inner_dict

        raise KeyError(key)

    def __setitem__(self, key: K, value: dict[K, dict]) -> None:
        self._data[key] = value
        self._on_entry_stored(key)

    def __delitem__(self, key: K) -> None:
        if key in self._data:
            del self._data[key]
        self._spilled_keys.discard(key)
        self._all_keys.discard(key)
        if key in self._lru_order:
            del self._lru_order[key]

    def __contains__(self, key: object) -> bool:
        return key in self._all_keys

    def __len__(self) -> int:
        return len(self._all_keys)

    def __iter__(self) -> Iterator[K]:
        yield from self._all_keys

    def get(self, key: K, default: dict[K, dict] | None = None) -> dict[K, dict] | None:  # type: ignore[override]
        try:
            return self[key]
        except KeyError:
            return default

    #
    #  LRU cache management
    #

    def _touch(self, key: K) -> None:
        if key in self._lru_order:
            self._lru_order.move_to_end(key)
        else:
            self._lru_order[key] = None

    def _on_entry_stored(self, key: K) -> None:
        self._all_keys.add(key)
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
            while len(self._data) > self._cache_limit + self._db_batch_size:
                to_evict = len(self._data) - self._cache_limit
                batch_size = min(self._db_batch_size, to_evict)
                if self._evict_n(batch_size) == 0:
                    break
                evicted_any = True
            return evicted_any

    def _evict_n(self, n: int) -> int:
        if not self._lru_order:
            return 0

        evicted = 0
        entries_to_save: list[tuple[K, dict[K, dict]]] = []

        for lru_key in list(self._lru_order):
            if evicted >= n:
                break

            if lru_key not in self._data:
                self._lru_order.pop(lru_key)
                continue

            inner_dict = self._data[lru_key]
            entries_to_save.append((lru_key, inner_dict))

            del self._data[lru_key]
            del self._lru_order[lru_key]
            self._spilled_keys.add(lru_key)
            evicted += 1

        if entries_to_save:
            self._save_to_lmdb(entries_to_save)

        return evicted

    #
    #  LMDB management
    #

    def _init_lmdb(self) -> None:
        if self._edgesdb is None and self.rtdb is not None:
            self._edgesdb = self.rtdb.open_db("edges")
            l.debug("Initialized edges LMDB cache.")

    def _cleanup_lmdb(self) -> None:
        if self._edgesdb is not None and self.rtdb is not None:
            self.rtdb.drop_db(self._edgesdb)
            self._edgesdb = None

    #
    #  Serialization helpers  (Edge protobuf)
    #

    @staticmethod
    def _serialize_edge_data(edge_data: dict) -> bytes:
        """Serialize an edge attribute dict to Edge protobuf bytes."""
        edge = primitives_pb2.Edge()
        jk = cfg_jumpkind_to_pb(edge_data.get("jumpkind"))
        edge.jumpkind = primitives_pb2.Edge.UnknownJumpkind if jk is None else jk
        v = edge_data.get("ins_addr")
        edge.ins_addr = v if v is not None else 0xFFFF_FFFF_FFFF_FFFF
        v = edge_data.get("stmt_idx")
        edge.stmt_idx = v if v is not None else -1
        return edge.SerializeToString()

    @staticmethod
    def _deserialize_edge_data(data: bytes) -> dict:
        """Deserialize Edge protobuf bytes to an edge attribute dict."""
        edge = primitives_pb2.Edge()
        edge.ParseFromString(data)
        return {
            "jumpkind": cfg_jumpkind_from_pb(edge.jumpkind),
            "ins_addr": edge.ins_addr if edge.ins_addr != 0xFFFF_FFFF_FFFF_FFFF else None,
            "stmt_idx": edge.stmt_idx if edge.stmt_idx != -1 else None,
        }

    @staticmethod
    def _serialize_inner_dict(inner_dict: dict[K, dict]) -> bytes:
        """Serialize an inner adjacency dict to bytes.

        Format::

            uint32  num_entries
            for each entry:
                uint32  dst_key_str_len
                bytes   dst_key_str          (UTF-8)
                uint32  edge_proto_len
                bytes   edge_proto_bytes     (Edge protobuf)
        """
        buf = bytearray()
        buf.extend(struct.pack(">I", len(inner_dict)))
        for dst_key, edge_data in inner_dict.items():
            key_bytes = repr(dst_key).encode("utf-8")
            proto_bytes = SpillingAdjDict._serialize_edge_data(edge_data)
            buf.extend(struct.pack(">I", len(key_bytes)))
            buf.extend(key_bytes)
            buf.extend(struct.pack(">I", len(proto_bytes)))
            buf.extend(proto_bytes)
        return bytes(buf)

    @staticmethod
    def _deserialize_inner_dict(data: bytes) -> dict[K, dict]:
        """Deserialize bytes back to an inner adjacency dict."""
        offset = 0
        (num_entries,) = struct.unpack_from(">I", data, offset)
        offset += 4

        inner_dict: dict[K, dict] = {}
        for _ in range(num_entries):
            (key_len,) = struct.unpack_from(">I", data, offset)
            offset += 4
            key_str = data[offset : offset + key_len].decode("utf-8")
            offset += key_len

            (proto_len,) = struct.unpack_from(">I", data, offset)
            offset += 4
            proto_bytes = data[offset : offset + proto_len]
            offset += proto_len

            dst_key = ast.literal_eval(key_str)
            edge_data = SpillingAdjDict._deserialize_edge_data(proto_bytes)
            inner_dict[dst_key] = edge_data

        return inner_dict

    #
    #  LMDB save / load
    #

    def _save_to_lmdb(self, entries: list[tuple[K, dict[K, dict]]]) -> None:
        if self.rtdb is None:
            return

        self._init_lmdb()

        while True:
            try:
                with self.rtdb.begin_txn(self._edgesdb, write=True) as txn:
                    for src_key, inner_dict in entries:
                        key = repr(src_key).encode("utf-8")
                        value = self._serialize_inner_dict(inner_dict)
                        txn.put(key, value)
                break
            except lmdb.MapFullError:
                self.rtdb.increase_lmdb_map_size()

    def _load_from_lmdb(self, key: K) -> dict[K, dict] | None:
        if self._edgesdb is None or self.rtdb is None:
            return None

        with self._db_load_lock:
            return self._load_from_lmdb_core(key)

    def _load_from_lmdb_core(self, key: K) -> dict[K, dict] | None:
        if self._loading_from_lmdb:
            raise RuntimeError("Recursive loading from LMDB detected. This is a bug.")

        self._loading_from_lmdb = True

        try:
            lmdb_key = repr(key).encode("utf-8")

            with self.rtdb.begin_txn(self._edgesdb) as txn:
                value = txn.get(lmdb_key)
                if value is None:
                    return None

                inner_dict = self._deserialize_inner_dict(value)

            self._spilled_keys.discard(key)
            self._data[key] = inner_dict
            self._on_entry_stored(key)

            return inner_dict
        finally:
            self._loading_from_lmdb = False

            if (
                self._eviction_enabled
                and self._cache_limit is not None
                and len(self._data) > self._cache_limit + self._db_batch_size
            ):
                self._evict_lru()

    def load_all_spilled(self) -> None:
        """Load all spilled entries back into memory."""
        if not self._spilled_keys:
            return

        old_eviction_state = self._eviction_enabled
        self._eviction_enabled = False

        try:
            for key in list(self._spilled_keys):
                self._load_from_lmdb(key)
        finally:
            self._eviction_enabled = old_eviction_state

    def evict_all_cached(self) -> None:
        """Evict all cached entries to LMDB."""
        if not self._data:
            return
        with self._db_store_lock:
            self._evict_n(len(self._data))

    #
    #  Pickling
    #

    def __getstate__(self) -> dict:
        self.load_all_spilled()
        return {
            "cache_limit": self._cache_limit,
            "db_batch_size": self._db_batch_size,
            "data": dict(self._data),
        }

    def __setstate__(self, state: dict) -> None:
        self._cache_limit = state["cache_limit"]
        self._db_batch_size = state["db_batch_size"]
        self._data = state["data"]
        self._spilled_keys = set()
        self._all_keys = set(self._data.keys())
        self.rtdb = None
        self._lru_order = OrderedDict()
        self._edgesdb = None
        self._eviction_enabled = True
        self._loading_from_lmdb = False
        self._db_load_lock = threading.Lock()
        self._db_store_lock = threading.Lock()

    #
    #  Copy
    #

    def copy(self) -> SpillingAdjDict:
        new_dict = SpillingAdjDict(
            self.rtdb,
            cache_limit=self._cache_limit,
            db_batch_size=self._db_batch_size,
        )
        new_dict._eviction_enabled = False

        new_dict._all_keys = set(self._all_keys)

        # Copy in-memory entries
        for key, inner_dict in self._data.items():
            new_dict._data[key] = {k: dict(v) for k, v in inner_dict.items()}
            new_dict._lru_order[key] = None

        # Copy spilled data from LMDB
        if self._spilled_keys and self._edgesdb is not None and self.rtdb is not None:
            new_dict._init_lmdb()
            with (
                self.rtdb.begin_txn(self._edgesdb) as src_txn,
                self.rtdb.begin_txn(new_dict._edgesdb, write=True) as dst_txn,
            ):
                for key in self._spilled_keys:
                    lmdb_key = repr(key).encode("utf-8")
                    value = src_txn.get(lmdb_key)
                    if value is not None:
                        dst_txn.put(lmdb_key, value)
                        new_dict._spilled_keys.add(key)

        new_dict._eviction_enabled = True
        return new_dict


class SpillingDiGraph(networkx.DiGraph):
    """
    A networkx DiGraph subclass whose ``adjlist_outer_dict_factory`` produces
    :class:`SpillingAdjDict` instances, enabling LRU-based LMDB spilling of
    adjacency data (edges and their attributes).

    :param rtdb:            RuntimeDb used for LMDB access.
    :param cache_limit:     Maximum adjacency entries to keep in memory per
                            outer dict (``_adj`` and ``_pred`` each).
    :param db_batch_size:   Number of entries evicted in a single batch.
    """

    def __init__(
        self,
        rtdb: RuntimeDb | None = None,
        cache_limit: int = 1000,
        db_batch_size: int = 200,
        **attr,
    ):
        self._rtdb = rtdb
        self._edge_cache_limit = cache_limit
        self._edge_db_batch_size = db_batch_size
        super().__init__(**attr)

    #
    #  Override adjlist_outer_dict_factory
    #

    @property
    def adjlist_outer_dict_factory(self):  # type: ignore[override]
        """Return a factory callable that creates :class:`SpillingAdjDict` instances."""
        rtdb = getattr(self, "_rtdb", None)
        cache_limit = getattr(self, "_edge_cache_limit", 1000)
        db_batch_size = getattr(self, "_edge_db_batch_size", 200)

        def _factory() -> SpillingAdjDict:
            return SpillingAdjDict(rtdb, cache_limit, db_batch_size)

        return _factory

    #
    #  Spilling helpers
    #

    def load_all_spilled_edges(self) -> None:
        """Load all spilled adjacency entries back into memory."""
        if isinstance(self._adj, SpillingAdjDict):
            self._adj.load_all_spilled()
        if isinstance(self._pred, SpillingAdjDict):
            self._pred.load_all_spilled()

    def evict_all_cached_edges(self) -> None:
        """Evict all cached adjacency entries to LMDB."""
        if isinstance(self._adj, SpillingAdjDict):
            self._adj.evict_all_cached()
        if isinstance(self._pred, SpillingAdjDict):
            self._pred.evict_all_cached()

    #
    #  Pickling
    #

    def __reduce__(self):
        # Load all spilled data before pickling
        self.load_all_spilled_edges()
        return super().__reduce__()
