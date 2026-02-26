"""
SpillingDiGraph - a networkx.DiGraph subclass with LMDB-backed edge spilling.

This module provides SpillingAdjDict and SpillingDiGraph classes that implement
disk-backed storage for graph adjacency data, following the SpillingCFGNodeDict pattern.

Edge attributes are serialized using the Edge protobuf message from primitives.proto.
"""
# pylint:disable=no-member

from __future__ import annotations

import logging
import struct
import threading
from collections import OrderedDict, UserDict
from collections.abc import Iterator, MutableMapping
from typing import TYPE_CHECKING, Any, TypeVar

import msgspec
import lmdb
import networkx
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor

from angr.protos import primitives_pb2, cfg_pb2
from angr.utils.enums_conv import cfg_jumpkind_to_pb, cfg_jumpkind_from_pb
from .types import K, CFG_ADDR_TYPES
from .block_id import BlockID

if TYPE_CHECKING:
    from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb

l = logging.getLogger(__name__)

DK = TypeVar("DK")
DV = TypeVar("DV")


class DirtyDict(UserDict[DK, DV]):
    """
    A simple dict subclass that tracks whether it has been modified since creation or last reset.

    This is used for edge attribute dicts to know when they need to be re-serialized and saved to LMDB.
    """

    def __init__(self, *args, dirty: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.dirty = dirty

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(key, value)
        self.dirty = True

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(key)
        self.dirty = True


class SpillingAdjDict(MutableMapping):
    """
    A dict-like container for adjacency data with LRU caching and LMDB spilling.

    Keys are node keys (block_key tuples), values are inner adjacency dicts (mapping neighbor_key -> edge_attr_dict).

    When the number of cached entries exceeds ``cache_limit + db_batch_size``, the ``db_batch_size`` least recently
    used entries are evicted to LMDB.

    Edge attributes within each inner dict are serialized/deserialized using the ``Edge`` protobuf message from
    ``primitives.proto``.
    """

    def __init__(
        self,
        addr_type: CFG_ADDR_TYPES,
        rtdb: RuntimeDb | None = None,
        cache_limit: int = 1000,
        db_batch_size: int = 800,
    ):
        self.addr_type: CFG_ADDR_TYPES = addr_type
        self._data: dict[K, DirtyDict[K, dict]] = {}
        self._spilled_keys: set[K] = set()

        self._cache_limit: int = cache_limit
        self._db_batch_size: int = db_batch_size

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

    def __getitem__(self, key: K) -> DirtyDict[K, dict]:
        if key in self._data:
            self._touch(key)
            return self._data[key]

        if key in self._spilled_keys:
            inner_dict = self._load_from_lmdb(key)
            if inner_dict is not None:
                return inner_dict

        raise KeyError(key)

    def __setitem__(self, key: K, value: DirtyDict[K, dict]) -> None:
        self._data[key] = value
        self._on_entry_stored(key)

    def __delitem__(self, key: K) -> None:
        if key in self._data:
            del self._data[key]
        self._spilled_keys.discard(key)
        if key in self._lru_order:
            del self._lru_order[key]

    def __contains__(self, key: object) -> bool:
        return key in self._data or key in self._spilled_keys

    def __len__(self) -> int:
        return len(self._data) + len(self._spilled_keys)

    def __iter__(self) -> Iterator[K]:
        yield from set(self._data) | set(self._spilled_keys)

    def get(self, key: K, default: dict[K, dict] | None = None) -> DirtyDict[K, dict] | None:  # type: ignore[override]
        try:
            return self[key]
        except KeyError:
            return DirtyDict(default, dirty=True) if default is not None else None

    #
    #  LRU cache management
    #

    def _touch(self, key: K) -> None:
        if key in self._lru_order:
            self._lru_order.move_to_end(key)
        else:
            self._lru_order[key] = None

    def _on_entry_stored(self, key: K) -> None:
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
        entries_to_save: list[tuple[K, DirtyDict[K, dict]]] = []

        for lru_key in list(self._lru_order):
            if evicted >= n:
                break

            if lru_key not in self._data:
                self._lru_order.pop(lru_key)
                continue

            inner_dict = self._data[lru_key]
            if inner_dict.dirty:
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
        edge = primitives_pb2.Edge()  # type:ignore
        jk = cfg_jumpkind_to_pb(edge_data.get("jumpkind"))
        edge.jumpkind = primitives_pb2.Edge.UnknownJumpkind if jk is None else jk  # type:ignore
        v = edge_data.get("ins_addr")
        edge.ins_addr = v if v is not None else 0xFFFF_FFFF_FFFF_FFFF
        v = edge_data.get("stmt_idx")
        edge.stmt_idx = v if v is not None else -1
        return edge.SerializeToString()

    @staticmethod
    def _deserialize_edge_data(data: bytes) -> dict:
        """Deserialize Edge protobuf bytes to an edge attribute dict."""
        edge = primitives_pb2.Edge()  # type:ignore
        edge.ParseFromString(data)
        return {
            "jumpkind": cfg_jumpkind_from_pb(edge.jumpkind),
            "ins_addr": edge.ins_addr if edge.ins_addr != 0xFFFF_FFFF_FFFF_FFFF else None,
            "stmt_idx": edge.stmt_idx if edge.stmt_idx != -1 else None,
        }

    def _serialize_inner_dict(self, inner_dict: DirtyDict[K, dict]) -> bytes:
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
        buf.extend(struct.pack("<I", len(inner_dict)))
        for dst_key, edge_data in inner_dict.items():
            match self.addr_type:
                case "int":
                    key_bytes = struct.pack("<Q", dst_key[0]) + struct.pack("<H", dst_key[1])

                case "block_id":
                    # dst_key: CFGENODE_K
                    assert isinstance(dst_key, tuple) and len(dst_key) == 3 and isinstance(dst_key[0], BlockID)
                    block_id = cfg_pb2.BlockIDProto()  # type:ignore
                    block_id.addr = dst_key[0].addr
                    block_id.jump_type = dst_key[0].jump_type
                    if dst_key[0].callsite_tuples is not None:
                        for val in dst_key[0].callsite_tuples:
                            entry = block_id.callsite_tuples.add()
                            if val is not None:
                                entry.has_value = True
                                entry.value = val
                    key_bytes = (
                        struct.pack("<I", dst_key[1]) + struct.pack("<H", dst_key[2]) + block_id.SerializeToString()
                    )

                case "soot":
                    # dst_key: SOOTNODE_K
                    assert isinstance(dst_key, SootAddressDescriptor)
                    d = {
                        "class_name": dst_key.method.class_name,
                        "name": dst_key.method.name,
                        "params": dst_key.method.params,
                        "block_idx": dst_key.block_idx,
                        "stmt_idx": dst_key.stmt_idx,
                    }
                    key_bytes = msgspec.json.encode(d)

                case _:
                    raise TypeError(f"Unsupported addr_type {self.addr_type}")

            proto_bytes = SpillingAdjDict._serialize_edge_data(edge_data)
            buf.extend(struct.pack("<H", len(key_bytes)))
            buf.extend(key_bytes)
            buf.extend(struct.pack("<I", len(proto_bytes)))
            buf.extend(proto_bytes)

        return bytes(buf)

    def _deserialize_inner_dict(self, data: bytes) -> DirtyDict[K, dict]:
        """Deserialize bytes back to an inner adjacency dict."""
        offset = 0
        num_entries = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        inner_dict: DirtyDict[K, dict] = DirtyDict()
        for _ in range(num_entries):
            key_len = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            key_bytes = data[offset : offset + key_len]
            offset += key_len

            match self.addr_type:
                case "int":
                    if len(key_bytes) != 10:
                        raise TypeError(f"Invalid key_bytes size for addr_type 'int': {len(key_bytes)}")
                    dst_key = struct.unpack("<QH", key_bytes)

                case "block_id":
                    if key_len <= 6:
                        raise ValueError(f"Invalid key length for block_id addr_type: {key_len}")
                    size = struct.unpack_from("<I", key_bytes, 0)[0]
                    looping_times = struct.unpack_from("<H", key_bytes, 4)[0]
                    block_id = cfg_pb2.BlockIDProto()  # type:ignore
                    block_id.ParseFromString(key_bytes[6:])
                    if block_id.HasField("callsite_tuples"):
                        callsite_tuples = tuple(
                            entry.value if entry.has_value else None for entry in block_id.callsite_tuples
                        )
                    else:
                        callsite_tuples = None
                    block_id_obj = BlockID(block_id.addr, callsite_tuples, block_id.jump_type)
                    dst_key = (block_id_obj, size, looping_times)

                case "soot":
                    d = msgspec.json.decode(key_bytes)
                    method = SootMethodDescriptor(d["class_name"], d["name"], d["params"])
                    dst_key = SootAddressDescriptor(method, d["block_idx"], d["stmt_idx"])

                case _:
                    raise TypeError(f"Unsupported addr_type {self.addr_type}")

            proto_len = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            proto_bytes = data[offset : offset + proto_len]
            offset += proto_len

            edge_data = SpillingAdjDict._deserialize_edge_data(proto_bytes)
            inner_dict[dst_key] = edge_data

        return inner_dict

    #
    #  LMDB save / load
    #

    def _save_to_lmdb(self, entries: list[tuple[K, DirtyDict[K, dict]]]) -> None:
        if self.rtdb is None:
            return

        self._init_lmdb()
        assert self._edgesdb is not None

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

    def _load_from_lmdb(self, key: K) -> DirtyDict[K, dict] | None:
        if self._edgesdb is None or self.rtdb is None:
            return None

        with self._db_load_lock:
            return self._load_from_lmdb_core(key)

    def _load_from_lmdb_core(self, key: K) -> DirtyDict[K, dict] | None:
        if self._loading_from_lmdb:
            raise RuntimeError("Recursive loading from LMDB detected. This is a bug.")

        assert self.rtdb is not None and self._edgesdb is not None

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
            self.addr_type,
            rtdb=self.rtdb,
            cache_limit=self._cache_limit,
            db_batch_size=self._db_batch_size,
        )
        new_dict._eviction_enabled = False

        # Copy in-memory entries
        for key, inner_dict in self._data.items():
            new_dict._data[key] = DirtyDict({k: dict(v) for k, v in inner_dict.items()}, dirty=True)
            new_dict._lru_order[key] = None

        # Copy spilled data from LMDB
        if self._spilled_keys and self._edgesdb is not None and self.rtdb is not None:
            new_dict._init_lmdb()
            assert new_dict._edgesdb is not None
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
    A networkx DiGraph subclass whose ``adjlist_outer_dict_factory`` produces :class:`SpillingAdjDict` instances,
    enabling LRU-based LMDB spilling of adjacency data (edges and their attributes).

    :param rtdb:            RuntimeDb used for LMDB access.
    :param edge_cache_limit:     Maximum adjacency entries to keep in memory per
                            outer dict (``_adj`` and ``_pred`` each).
    :param db_batch_size:   Number of entries evicted in a single batch.
    """

    _adj: SpillingAdjDict
    _pred: SpillingAdjDict

    def __init__(
        self,
        rtdb: RuntimeDb | None = None,
        edge_cache_limit: int = 1000,
        db_batch_size: int = 2400,
        addr_type: CFG_ADDR_TYPES = "int",
        **attr,
    ):
        self._rtdb = rtdb
        self._edge_cache_limit = edge_cache_limit
        self._edge_db_batch_size = db_batch_size
        self._addr_type: CFG_ADDR_TYPES = addr_type
        super().__init__(**attr)

    def adjlist_outer_dict_factory(self) -> SpillingAdjDict:  # type:ignore
        return SpillingAdjDict(self.addr_type, self._rtdb, self._edge_cache_limit, self._edge_db_batch_size)

    @staticmethod
    def adjlist_inner_dict_factory(self) -> DirtyDict:  # type:ignore
        return DirtyDict(dirty=True)

    @property
    def addr_type(self) -> CFG_ADDR_TYPES:
        return self._addr_type

    @addr_type.setter
    def addr_type(self, value: str) -> None:
        # you shouldn't change addr_type once the first adjlist_outer_dict has been created.
        if value not in ("int", "block_id", "soot"):
            raise ValueError(f"Invalid addr_type {value}, must be 'int', 'block_id', or 'soot'")
        self._addr_type = value

    #
    #  Spilling helpers
    #

    def load_all_spilled_edges(self) -> None:
        """Load all spilled adjacency entries back into memory."""
        self._adj.load_all_spilled()
        self._pred.load_all_spilled()

    def evict_all_cached_edges(self) -> None:
        """Evict all cached adjacency entries to LMDB."""
        self._adj.evict_all_cached()
        self._pred.evict_all_cached()

    #
    #  Pickling
    #

    def __reduce__(self):
        # Load all spilled data before pickling
        self.load_all_spilled_edges()
        return super().__reduce__()
