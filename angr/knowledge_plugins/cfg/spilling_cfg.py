# pylint:disable=protected-access
"""
CFG graph storage: CFGNode instances live in SpillingCFGNodeDict (LRU caching + LMDB spilling, following the
SpillingFunctionDict pattern); the graph structure and edge attributes live in the packed Rust store CfgGraph.
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
import uuid
import weakref
from collections import OrderedDict, defaultdict
from collections.abc import Generator, Iterator
from typing import TYPE_CHECKING, Literal, overload

import lmdb
import networkx
from archinfo.arch_soot import SootAddressDescriptor

from angr.protos import cfg_pb2
from angr.rustylib.cfg_graph import PRESENT_INS_ADDR, PRESENT_JUMPKIND, PRESENT_STMT_IDX, CfgGraph

from .block_id import BlockID
from .cfg_node import CFGENode, CFGNode
from .types import CFG_ADDR_TYPES, CFGENODE_K, CFGNODE_K, SOOTNODE_K, K

if TYPE_CHECKING:
    from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb

    from .cfg_model import CFGModel

l = logging.getLogger(name=__name__)


# a global flag to disable SpillingFunctionDict usage; mainly for testing purposes
USE_SPILLING_CFGNODE_DICT = os.environ.get("USE_SPILLING_CFGNODE_DICT", "True").lower() not in ("0", "false", "no")


class SpillingCFGNodeDict:
    """
    A dict-like container for CFGNode instances with LRU caching and LMDB spilling.

    This class keeps only the most recently accessed N nodes in memory, spilling others to an LMDB database on disk.

    :ivar cache_limit:          The maximum number of nodes to keep in memory.
    :ivar rtdb:                 A reference to the RuntimeDb knowledge base plugin.
    :ivar _lru_order:           An OrderedDict tracking the eviction order of cached nodes.
    :ivar _spilled_keys:        A set of block_ids that have been spilled to LMDB.
    :ivar _db_batch_size:       The number of nodes that are evicted in a single batch.
    :ivar _eviction_enabled:    A flag indicating whether eviction is currently enabled.
    """

    def __init__(
        self,
        rtdb: RuntimeDb | None,
        cfg_model: CFGModel | None = None,
        cache_limit: int = 1000,
        db_batch_size: int = 200,
    ):
        self._data: dict[K, CFGNode] = {}
        self._spilled_keys: set[K] = set()

        self._cache_limit: int = cache_limit
        self._db_batch_size: int = db_batch_size

        self.rtdb: RuntimeDb | None = rtdb
        self._cfg_model_ref: weakref.ref[CFGModel] | None = weakref.ref(cfg_model) if cfg_model is not None else None

        self._lru_order: OrderedDict[K, None] = OrderedDict()

        self._nodesdb: str | None = None
        self._eviction_enabled: bool = True
        self._loading_from_lmdb: bool = False
        self._db_load_lock = threading.Lock()
        self._db_store_lock = threading.Lock()

    def __del__(self):
        self._cleanup_lmdb()

    @property
    def _cfg_model(self) -> CFGModel | None:
        if self._cfg_model_ref is None:
            return None
        return self._cfg_model_ref()

    @_cfg_model.setter
    def _cfg_model(self, value: CFGModel | None) -> None:
        self._cfg_model_ref = weakref.ref(value) if value is not None else None

    def __getitem__(self, block_key: K) -> CFGNode:
        # First try to get from in-memory cache
        if block_key in self._data:
            self._touch(block_key)
            return self._data[block_key]

        # Try to load from LMDB if spilled
        if block_key in self._spilled_keys:
            node = self._load_from_lmdb(block_key)
            if node is not None:
                return node

        raise KeyError(block_key)

    def __setitem__(self, block_key: K, node: CFGNode) -> None:
        self._data[block_key] = node
        self._on_node_stored(block_key)

    def __delitem__(self, block_key: K) -> None:
        # Remove from in-memory cache if present
        if block_key in self._data:
            del self._data[block_key]
        # Remove from spilled set if present
        self._spilled_keys.discard(block_key)
        # Remove from LRU order
        if block_key in self._lru_order:
            del self._lru_order[block_key]

    def __contains__(self, block_key: K) -> bool:
        return block_key in self._data or block_key in self._spilled_keys

    def __len__(self) -> int:
        return len(self._data) + len(self._spilled_keys)

    def __iter__(self) -> Iterator[K]:
        # Iterate over all block_keys
        yield from list(self._data) + list(self._spilled_keys)

    def get(self, block_key: K, default: CFGNode | None = None) -> CFGNode | None:
        try:
            return self[block_key]
        except KeyError:
            return default

    def keys(self) -> Iterator[K]:
        return iter(self)

    def values(self) -> Iterator[CFGNode]:
        for block_key in self:
            yield self[block_key]

    def items(self) -> Iterator[tuple[K, CFGNode]]:
        for block_key in self:
            yield block_key, self[block_key]

    def clear(self) -> None:
        self._data.clear()
        self._lru_order.clear()
        self._spilled_keys.clear()
        self._cleanup_lmdb()

    def copy(self) -> SpillingCFGNodeDict:
        new_dict = SpillingCFGNodeDict(
            self.rtdb,
            self._cfg_model,
            cache_limit=self._cache_limit,
            db_batch_size=self._db_batch_size,
        )
        # Temporarily disable eviction during copy
        new_dict._eviction_enabled = False

        # Copy in-memory nodes
        for block_key, node in self._data.items():
            new_dict._data[block_key] = node.copy()
            new_dict._lru_order[block_key] = None

        # Copy spilled data from LMDB
        if self._spilled_keys and self._nodesdb is not None and self.rtdb is not None:
            new_dict._init_lmdb()
            assert new_dict._nodesdb is not None
            with (
                self.rtdb.begin_txn(self._nodesdb) as src_txn,
                self.rtdb.begin_txn(new_dict._nodesdb, write=True) as dst_txn,
            ):
                for block_key in self._spilled_keys:
                    key = str(block_key).encode("utf-8")
                    value = src_txn.get(key)
                    if value is not None:
                        dst_txn.put(key, value)
                        new_dict._spilled_keys.add(block_key)

        new_dict._eviction_enabled = True
        return new_dict

    #
    # Properties
    #

    @property
    def cache_limit(self) -> int:
        return self._cache_limit

    @cache_limit.setter
    def cache_limit(self, value: int) -> None:
        self._cache_limit = value
        # Trigger eviction if we're over the new limit
        if self.cached_count > value + self._db_batch_size:
            self._evict_lru()

    @property
    def db_batch_size(self) -> int:
        return self._db_batch_size

    @db_batch_size.setter
    def db_batch_size(self, value: int) -> None:
        self._db_batch_size = value
        if self.cached_count > self._cache_limit + value:
            self._evict_lru()

    @property
    def cached_count(self) -> int:
        return len(self._data)

    @property
    def spilled_count(self) -> int:
        return len(self._spilled_keys)

    @property
    def total_count(self) -> int:
        return len(self._spilled_keys) + len(self._data)

    def is_cached(self, block_key: K) -> bool:
        return block_key in self._data

    #
    # LRU Cache Management
    #

    def _touch(self, block_key: K) -> None:
        if block_key in self._lru_order:
            self._lru_order.move_to_end(block_key)
        else:
            self._lru_order[block_key] = None

    def _on_node_stored(self, block_key: K) -> None:
        self._touch(block_key)
        self._spilled_keys.discard(block_key)

        if (
            self._eviction_enabled
            and self._cache_limit is not None
            and self.cached_count > self._cache_limit + self._db_batch_size
        ):
            self._evict_lru()

    def _evict_lru(self) -> bool:
        with self._db_store_lock:
            evicted_any = False
            while self.cached_count > self._cache_limit + self._db_batch_size:
                # Evict enough to get below the limit, in batches
                to_evict = self.cached_count - self._cache_limit
                batch_size = min(self._db_batch_size, to_evict)
                if self._evict_n(batch_size) == 0:
                    break
                evicted_any = True
            return evicted_any

    def _evict_n(self, n: int) -> int:
        if self.rtdb is None:
            # without a RuntimeDb we cannot persist evicted nodes; evicting anyway would silently lose data
            # (this happens e.g. while unpickling, before an rtdb is re-attached via CFGManager.set_kb()).
            return 0
        if not self._lru_order:
            return 0

        evicted = 0
        nodes_to_save = []
        nodes_to_evict = []
        for lru_block_key in self._lru_order:
            if evicted >= n:
                break

            if lru_block_key not in self._data:
                nodes_to_evict.append(lru_block_key)
                continue

            node = self._data[lru_block_key]
            if node.dirty:
                nodes_to_save.append((lru_block_key, node))

            del self._data[lru_block_key]
            nodes_to_evict.append(lru_block_key)
            self._spilled_keys.add(lru_block_key)
            evicted += 1

        for key in nodes_to_evict:
            del self._lru_order[key]

        if nodes_to_save:
            self._save_to_lmdb(nodes_to_save)

        return evicted

    #
    # LMDB Management
    #

    def _init_lmdb(self) -> None:
        if self._nodesdb is None and self.rtdb is not None:
            self._nodesdb = self.rtdb.open_db("cfgnodes")
            l.debug("Initialized CFGNode LMDB cache.")

    def _cleanup_lmdb(self) -> None:
        if self._nodesdb is not None and self.rtdb is not None:
            self.rtdb.drop_db(self._nodesdb)
            self._nodesdb = None

    def _save_to_lmdb(self, nodes: list[tuple[K, CFGNode]]) -> None:
        if self.rtdb is None:
            return

        self._init_lmdb()
        assert self._nodesdb is not None

        while True:
            try:
                with self.rtdb.begin_txn(self._nodesdb, write=True) as txn:
                    for block_key, node in nodes:
                        cmsg = node.serialize_to_cmessage()
                        payload = cmsg.SerializeToString()
                        # Prefix with type byte: 0x00 for CFGNode, 0x01 for CFGENode
                        data = b"\x01" + payload if isinstance(node, CFGENode) else b"\x00" + payload
                        key = str(block_key).encode("utf-8")
                        txn.put(key, data)
                break
            except lmdb.MapFullError:
                if not self.rtdb.increase_lmdb_map_size():
                    raise

    def _load_from_lmdb(self, block_key: K) -> CFGNode | None:
        if self._nodesdb is None or self.rtdb is None:
            return None

        with self._db_load_lock:
            return self._load_from_lmdb_core(block_key)

    def _load_from_lmdb_core(self, block_key: K) -> CFGNode | None:
        if self._loading_from_lmdb:
            raise RuntimeError("Recursive loading from LMDB detected. This is a bug.")

        assert self.rtdb is not None and self._nodesdb is not None

        self._loading_from_lmdb = True

        try:
            key = str(block_key).encode("utf-8")

            with self.rtdb.begin_txn(self._nodesdb) as txn:
                value = txn.get(key)
                if value is None:
                    return None

                type_byte = value[0]
                payload = value[1:]

                if type_byte == 0x00:
                    cmsg = cfg_pb2.CFGNode()  # type:ignore  # pylint:disable=no-member
                    cmsg.ParseFromString(payload)
                    node = CFGNode.parse_from_cmessage(cmsg, cfg=self._cfg_model)
                elif type_byte == 0x01:
                    cmsg = cfg_pb2.CFGENode()  # type:ignore  # pylint:disable=no-member
                    cmsg.ParseFromString(payload)
                    node = CFGENode.parse_from_cmessage(cmsg, cfg=self._cfg_model)
                else:
                    raise ValueError(f"Unknown node type byte: {type_byte:#x}")

                node.dirty = False

            # Remove from spilled set and add to cache
            self._spilled_keys.discard(block_key)
            self._data[block_key] = node
            self._on_node_stored(block_key)

            return node
        finally:
            self._loading_from_lmdb = False

            if (
                self._eviction_enabled
                and self._cache_limit is not None
                and self.cached_count > self._cache_limit + self._db_batch_size
            ):
                self._evict_lru()

    def bulk_import_serialized(self, items: list[tuple[K, bytes]]) -> None:
        """
        Bulk-import already-serialized CFG nodes directly into the LMDB backing store and register them as spilled,
        without deserializing them. Each payload must be in the format that _save_to_lmdb() writes: a type byte (0x00
        for CFGNode, 0x01 for CFGENode) followed by the serialized protobuf message.

        :param items:   A list of (block key, serialized node payload) tuples.
        """

        if not items or self.rtdb is None:
            return

        self._init_lmdb()
        assert self._nodesdb is not None

        with self._db_store_lock:
            while True:
                try:
                    with self.rtdb.begin_txn(self._nodesdb, write=True) as txn:
                        for block_key, payload in items:
                            txn.put(str(block_key).encode("utf-8"), payload)
                    break
                except lmdb.MapFullError:
                    # Increase map size and retry
                    if not self.rtdb.increase_lmdb_map_size():
                        raise

            for block_key, _ in items:
                if block_key in self._data:
                    # drop the stale in-memory copy; LMDB now holds the authoritative data
                    del self._data[block_key]
                    self._lru_order.pop(block_key, None)
                self._spilled_keys.add(block_key)

    def load_all_spilled(self) -> None:
        if not self._spilled_keys:
            return

        old_eviction_state = self._eviction_enabled
        self._eviction_enabled = False

        try:
            block_keys_to_load = list(self._spilled_keys)
            for block_key in block_keys_to_load:
                self._load_from_lmdb(block_key)
        finally:
            self._eviction_enabled = old_eviction_state

    def evict_all_cached(self) -> None:
        if self.cached_count == 0:
            return
        with self._db_store_lock:
            self._evict_n(self.cached_count)

    #
    # Pickling
    #

    def __getstate__(self):
        # Load all spilled nodes before pickling.
        # We load the entire node store into memory (make sure there is enough RAM!); otherwise we will lose data.
        self.load_all_spilled()
        return {
            "cache_limit": self._cache_limit,
            "db_batch_size": self._db_batch_size,
            "items": dict(self._data),
        }

    def __setstate__(self, state: dict):
        self._cache_limit = state["cache_limit"]
        self._db_batch_size = state["db_batch_size"]
        self._data = {}
        self.rtdb = None
        self._cfg_model_ref = None
        self._lru_order = OrderedDict()
        self._spilled_keys = set()
        self._nodesdb = None
        self._eviction_enabled = True
        self._loading_from_lmdb = False
        self._db_load_lock = threading.Lock()
        self._db_store_lock = threading.Lock()

        for k, v in state["items"].items():
            # nodes restored from a pickle have no LMDB backing store behind them; mark them dirty so that
            # they will be written out if they are ever evicted again (after an rtdb is re-attached)
            v.dirty = True
            self[k] = v


class _IntKeys:
    """
    Key table for ``addr_type == "int"``: block keys are ``(addr, size)`` and the Rust store is the table.
    """

    __slots__ = ("_g",)

    def __init__(self, graph: CfgGraph):
        self._g = graph

    def bind(self, graph: CfgGraph) -> None:
        self._g = graph

    def id_of(self, key: K) -> int | None:
        return self._g.find_node(key[0], key[1])  # type:ignore[index]

    def add(self, key: K, addr: int | SootAddressDescriptor) -> int:
        if key[0] != addr:  # type:ignore[index]
            raise TypeError(f"block key {key!r} does not start with the node address {addr!r}")
        return self._g.add_node(key[0], key[1])[0]  # type:ignore[index]

    def remove(self, key: K, addr: int | SootAddressDescriptor) -> None:
        pass

    def key_of(self, idx: int) -> K:
        return self._g.node_key(idx)

    def block_keys(self) -> list[K]:
        return self._g.node_keys()  # type:ignore[return-value]

    def keys_at(self, addr: int | SootAddressDescriptor) -> list[K]:
        g = self._g
        return [g.node_key(i) for i in g.nodes_at_addr(addr)]  # type:ignore[arg-type]

    def first_key_at(self, addr: int | SootAddressDescriptor) -> K | None:
        idx = self._g.first_node_at_addr(addr)  # type:ignore[arg-type]
        return None if idx is None else self._g.node_key(idx)

    def has_addr(self, addr: int | SootAddressDescriptor) -> bool:
        return self._g.has_addr(addr)  # type:ignore[arg-type]

    def addrs(self) -> list[int | SootAddressDescriptor]:
        return self._g.addrs()  # type:ignore[return-value]

    def clear(self) -> None:
        pass

    def copy(self, graph: CfgGraph) -> _IntKeys:
        return _IntKeys(graph)


class _ObjKeys:
    """
    Key table for ``addr_type in ("block_id", "soot")``: block keys are interned, and the Rust store sees the opaque
    key ``(id, 0)``.
    """

    __slots__ = ("_g", "_id_to_key", "_key_to_id", "_keys_by_addr", "_next")

    def __init__(self, graph: CfgGraph):
        self._g = graph
        self._key_to_id: dict[K, int] = {}
        self._id_to_key: dict[int, K] = {}
        self._keys_by_addr: dict[int | SootAddressDescriptor, set[K]] = defaultdict(set)
        # opaque "address" handed to the store; node ids may be reused after removals, this never is
        self._next = 0

    def bind(self, graph: CfgGraph) -> None:
        self._g = graph

    def id_of(self, key: K) -> int | None:
        return self._key_to_id.get(key)

    def add(self, key: K, addr: int | SootAddressDescriptor) -> int:
        idx = self._key_to_id.get(key)
        if idx is not None:
            return idx
        idx = self._g.add_node(self._next, 0)[0]
        self._next += 1
        self._id_to_key[idx] = key
        self._key_to_id[key] = idx
        self._keys_by_addr[addr].add(key)
        return idx

    def remove(self, key: K, addr: int | SootAddressDescriptor) -> None:
        idx = self._key_to_id.pop(key, None)
        if idx is not None:
            del self._id_to_key[idx]
        keys = self._keys_by_addr.get(addr)
        if keys is not None:
            keys.discard(key)
            if not keys:
                del self._keys_by_addr[addr]

    def key_of(self, idx: int) -> K:
        return self._id_to_key[idx]

    def block_keys(self) -> list[K]:
        id_to_key = self._id_to_key
        return [id_to_key[i] for i in self._g.nodes()]

    def keys_at(self, addr: int | SootAddressDescriptor) -> list[K]:
        return list(self._keys_by_addr.get(addr, ()))

    def first_key_at(self, addr: int | SootAddressDescriptor) -> K | None:
        return next(iter(self._keys_by_addr.get(addr, ())), None)

    def has_addr(self, addr: int | SootAddressDescriptor) -> bool:
        return addr in self._keys_by_addr

    def addrs(self) -> list[int | SootAddressDescriptor]:
        return list(self._keys_by_addr)

    def clear(self) -> None:
        self._key_to_id.clear()
        self._id_to_key.clear()
        self._keys_by_addr.clear()
        self._next = 0

    def copy(self, graph: CfgGraph) -> _ObjKeys:
        new = _ObjKeys(graph)
        new._key_to_id = dict(self._key_to_id)
        new._id_to_key = dict(self._id_to_key)
        new._next = self._next
        for addr, keys in self._keys_by_addr.items():
            new._keys_by_addr[addr] = set(keys)
        return new

    def __getstate__(self) -> dict:
        return {"id_to_key": self._id_to_key, "keys_by_addr": dict(self._keys_by_addr), "next": self._next}

    def __setstate__(self, state: dict) -> None:
        self._g = None  # type:ignore[assignment]  # re-bound by SpillingCFG.__setstate__
        self._id_to_key = state["id_to_key"]
        self._key_to_id = {key: idx for idx, key in self._id_to_key.items()}
        self._keys_by_addr = defaultdict(set, state["keys_by_addr"])
        self._next = state["next"]


class CFGSegmentStore:
    """
    Backend for paged :class:`CfgGraph` segments on the RuntimeDb: one LMDB sub-database shared by every graph of
    the knowledge base, keys prefixed with a per-graph random id.
    """

    DB_NAME = "cfgsegments"

    def __init__(self, rtdb: RuntimeDb):
        self.rtdb = rtdb
        self._db = rtdb.open_db(self.DB_NAME, unique=False)
        self._prefix = uuid.uuid4().bytes

    def _key(self, window: int) -> bytes:
        return self._prefix + window.to_bytes(8, "big")

    def get(self, window: int) -> bytes | None:
        with self.rtdb.begin_txn(self._db) as txn:
            return txn.get(self._key(window))

    def put(self, window: int, data: bytes) -> None:
        while True:
            try:
                with self.rtdb.begin_txn(self._db, write=True) as txn:
                    txn.put(self._key(window), data)
                return
            except lmdb.MapFullError:
                if not self.rtdb.increase_lmdb_map_size():
                    raise

    def delete(self, window: int) -> None:
        with self.rtdb.begin_txn(self._db, write=True) as txn:
            txn.delete(self._key(window))

    def delete_all(self) -> None:
        with self.rtdb.begin_txn(self._db, write=True) as txn:
            cursor = txn.cursor()
            if cursor.set_range(self._prefix):
                while cursor.key().startswith(self._prefix) and cursor.delete():
                    pass

    def __del__(self):
        with contextlib.suppress(Exception):
            self.delete_all()


class _AdjacencyDict:
    """Helper class to support graph[src][dst] access pattern."""

    def __init__(self, graph: SpillingCFG, src_id: int):
        self._graph = graph
        self._src_id = src_id

    def __getitem__(self, dst_node: CFGNode) -> dict:
        dst_id = self._graph._id_of_node(dst_node)
        data = None if dst_id is None else self._graph._edge_data(self._src_id, dst_id)
        if data is None:
            raise KeyError(dst_node)
        return data

    def __contains__(self, dst_node: CFGNode) -> bool:
        dst_id = self._graph._id_of_node(dst_node)
        return dst_id is not None and self._graph._graph.has_edge(self._src_id, dst_id)

    def keys(self) -> Iterator[CFGNode]:
        for dst_id in self._graph._graph.successors(self._src_id):
            yield self._graph._node_of_id(dst_id)

    def values(self) -> Iterator[dict]:
        for _, dst_id, data in self._graph._graph.out_edges_with_data(self._src_id):
            yield self._graph._merge_extra(self._src_id, dst_id, data)

    def items(self) -> Iterator[tuple[CFGNode, dict]]:
        for _, dst_id, data in self._graph._graph.out_edges_with_data(self._src_id):
            yield self._graph._node_of_id(dst_id), self._graph._merge_extra(self._src_id, dst_id, data)

    def __iter__(self) -> Iterator[CFGNode]:
        return self.keys()

    def __len__(self) -> int:
        return self._graph._graph.out_degree(self._src_id)


class _NodeView:
    """View over graph nodes supporting len(), iteration, and call with data=True."""

    def __init__(self, graph: SpillingCFG):
        self._graph = graph

    def __len__(self) -> int:
        return self._graph._graph.number_of_nodes()

    def __iter__(self) -> Iterator[CFGNode]:
        return iter(self._graph)

    @overload
    def __call__(self, data: Literal[False] = False) -> Iterator[CFGNode]: ...
    @overload
    def __call__(self, data: Literal[True]) -> Iterator[tuple[CFGNode, dict]]: ...

    def __call__(self, data: bool = False) -> Iterator[CFGNode] | Iterator[tuple[CFGNode, dict]]:
        if data:
            node_attrs = self._graph._node_attrs
            for key in self._graph._keys.block_keys():
                yield self._graph.get_node_by_key(key), node_attrs.get(key, {})
        else:
            yield from self._graph

    def __contains__(self, node: CFGNode) -> bool:
        return self._graph.has_node(node)


class _EdgeView:
    """View over graph edges supporting len(), iteration, and call with data=True."""

    def __init__(self, graph: SpillingCFG):
        self._graph = graph

    def __len__(self) -> int:
        return self._graph._graph.number_of_edges()

    def __iter__(self) -> Iterator[tuple[CFGNode, CFGNode]]:
        g = self._graph
        for src_id, dst_id in g._graph.edges():
            yield g._node_of_id(src_id), g._node_of_id(dst_id)

    @overload
    def __call__(self, data: Literal[False] = False) -> Iterator[tuple[CFGNode, CFGNode]]: ...
    @overload
    def __call__(self, data: Literal[True]) -> Iterator[tuple[CFGNode, CFGNode, dict]]: ...

    def __call__(
        self, data: bool = False
    ) -> Iterator[tuple[CFGNode, CFGNode]] | Iterator[tuple[CFGNode, CFGNode, dict]]:
        if data:
            g = self._graph
            for src_id, dst_id, edge_data in g._graph.edges_with_data():
                yield g._node_of_id(src_id), g._node_of_id(dst_id), g._merge_extra(src_id, dst_id, edge_data)
        else:
            yield from self


class _InEdgeView:
    """View over graph in-edges supporting call, subscript, len, and iteration.

    Supports both ``graph.in_edges(node)`` and ``graph.in_edges[node]``.
    """

    def __init__(self, graph: SpillingCFG):
        self._graph = graph

    @overload
    def __call__(self, nbunch=None, data: Literal[False] = False) -> list[tuple[CFGNode, CFGNode]]: ...
    @overload
    def __call__(self, nbunch=None, *, data: Literal[True]) -> list[tuple[CFGNode, CFGNode, dict]]: ...

    def __call__(
        self, nbunch=None, data: bool = False
    ) -> list[tuple[CFGNode, CFGNode]] | list[tuple[CFGNode, CFGNode, dict]]:
        g = self._graph
        if nbunch is None:
            if data:
                return list(g.edges(data=True))
            return list(g.edges())
        ids = g._ids_of_nbunch(nbunch)
        if data:
            return [
                (g._node_of_id(src_id), g._node_of_id(dst_id), g._merge_extra(src_id, dst_id, edge_data))
                for idx in ids
                for src_id, dst_id, edge_data in g._graph.in_edges_with_data(idx)
            ]
        return [
            (g._node_of_id(src_id), g._node_of_id(dst_id)) for idx in ids for src_id, dst_id in g._graph.in_edges(idx)
        ]

    def __getitem__(self, node) -> list[tuple[CFGNode, CFGNode]]:
        return self(node)

    def __iter__(self) -> Iterator[tuple[CFGNode, CFGNode]]:
        return iter(self._graph.edges)

    def __len__(self) -> int:
        return self._graph._graph.number_of_edges()


class _OutEdgeView:
    """View over graph out-edges supporting call, subscript, len, and iteration.

    Supports both ``graph.out_edges(node)`` and ``graph.out_edges[node]``.
    """

    def __init__(self, graph: SpillingCFG):
        self._graph = graph

    @overload
    def __call__(self, nbunch=None, data: Literal[False] = False) -> list[tuple[CFGNode, CFGNode]]: ...
    @overload
    def __call__(self, nbunch=None, *, data: Literal[True]) -> list[tuple[CFGNode, CFGNode, dict]]: ...

    def __call__(
        self, nbunch=None, data: bool = False
    ) -> list[tuple[CFGNode, CFGNode]] | list[tuple[CFGNode, CFGNode, dict]]:
        g = self._graph
        if nbunch is None:
            if data:
                return list(g.edges(data=True))
            return list(g.edges())
        ids = g._ids_of_nbunch(nbunch)
        if data:
            return [
                (g._node_of_id(src_id), g._node_of_id(dst_id), g._merge_extra(src_id, dst_id, edge_data))
                for idx in ids
                for src_id, dst_id, edge_data in g._graph.out_edges_with_data(idx)
            ]
        return [
            (g._node_of_id(src_id), g._node_of_id(dst_id)) for idx in ids for src_id, dst_id in g._graph.out_edges(idx)
        ]

    def __getitem__(self, node) -> list[tuple[CFGNode, CFGNode]]:
        return self(node)

    def __iter__(self) -> Iterator[tuple[CFGNode, CFGNode]]:
        return iter(self._graph.edges)

    def __len__(self) -> int:
        return self._graph._graph.number_of_edges()


class _InDegreeView:
    """View over graph in-degrees supporting call, subscript, len, and iteration.

    Supports both ``graph.in_degree(node)`` and ``graph.in_degree[node]``.
    """

    def __init__(self, graph: SpillingCFG):
        self._graph = graph

    def __call__(self, node: CFGNode | None = None) -> int | Iterator[tuple[CFGNode, int]]:
        if node is None:
            return iter(self)
        return self[node]

    def __getitem__(self, node: CFGNode) -> int:
        idx = self._graph._id_of_node(node)
        return 0 if idx is None else self._graph._graph.in_degree(idx)

    def __iter__(self) -> Iterator[tuple[CFGNode, int]]:
        g = self._graph
        for idx in g._graph.nodes():
            yield g._node_of_id(idx), g._graph.in_degree(idx)

    def __len__(self) -> int:
        return self._graph._graph.number_of_nodes()


class _OutDegreeView:
    """View over graph out-degrees supporting call, subscript, len, and iteration.

    Supports both ``graph.out_degree(node)`` and ``graph.out_degree[node]``.
    """

    def __init__(self, graph: SpillingCFG):
        self._graph = graph

    def __call__(self, node: CFGNode | None = None) -> int | Iterator[tuple[CFGNode, int]]:
        if node is None:
            return iter(self)
        return self[node]

    def __getitem__(self, node: CFGNode) -> int:
        idx = self._graph._id_of_node(node)
        return 0 if idx is None else self._graph._graph.out_degree(idx)

    def __iter__(self) -> Iterator[tuple[CFGNode, int]]:
        g = self._graph
        for idx in g._graph.nodes():
            yield g._node_of_id(idx), g._graph.out_degree(idx)

    def __len__(self) -> int:
        return self._graph._graph.number_of_nodes()


@overload
def get_block_key(node: CFGNode) -> CFGNODE_K | SOOTNODE_K: ...
@overload
def get_block_key(node: CFGENode) -> CFGENODE_K: ...  # type:ignore


def get_block_key(node: CFGNode | CFGENode) -> K:
    """
    Get the unique identifier for a CFGNode. Typically this unique identifier contains the address of the block and
    the looping_times of the block (in case there are multiple blocks with the same address, which may happen after
    loop unrolling in a CFGEmulated instance).

    :param node:    The CFGNode or CFGENode instance to get the block key for.
    :return:        The unique identifier.
    """

    if isinstance(node.addr, SootAddressDescriptor):
        return node.addr

    block_id = node.block_id
    if block_id is None:
        block_id = node.addr
    block_key = block_id, node.size if node.size is not None else -1

    if isinstance(node, CFGENode):
        return *block_key, node.looping_times if node.looping_times is not None else 0
    return block_key


@overload
def block_key_to_addr(block_key: CFGNODE_K | CFGENODE_K) -> int: ...
@overload
def block_key_to_addr(block_key: SOOTNODE_K) -> SootAddressDescriptor: ...


def block_key_to_addr(block_key: K) -> int | SootAddressDescriptor:
    """Extract the address from a block key."""
    if isinstance(block_key, SootAddressDescriptor):
        return block_key
    if isinstance(block_key, tuple) and len(block_key) >= 2:
        item = block_key[0]
        if isinstance(item, BlockID):
            return item.addr
        assert isinstance(item, int)
        return item
    raise ValueError(f"Invalid block key format: {block_key!r}")


def block_key_to_size(block_key: K) -> int | None:
    """Extract the size from a block key, if present."""
    if isinstance(block_key, SootAddressDescriptor):
        return None
    if isinstance(block_key, tuple) and len(block_key) >= 2:
        size = block_key[1]
        return size if size != -1 else None
    raise ValueError(f"Invalid block key format: {block_key!r}")


_STD_EDGE_KEYS = frozenset(("jumpkind", "ins_addr", "stmt_idx"))


class SpillingCFG:
    """
    A graph wrapper that stores CFGNode instances in a spilling dict while keeping the graph structure in a packed
    Rust store (:class:`CfgGraph`) keyed by block keys.

    This provides a networkx-compatible interface while supporting disk-backed storage for the nodes of large CFGs.

    addr_type must be "int", "block_id", or "soot". You can change addr_type before the first node is inserted but not
    after, since it affects how keys are mapped onto the store.
    """

    _addr_type: CFG_ADDR_TYPES

    def __init__(
        self,
        rtdb: RuntimeDb | None = None,
        cfg_model: CFGModel | None = None,
        cache_limit: int | None = None,
        db_batch_size: int = 800,
        addr_type: CFG_ADDR_TYPES = "int",
        segment_budget: int | None = None,
    ):
        """
        :param segment_budget:  Byte budget for resident graph segments; the graph is paged to the RuntimeDb from
                                the start. Setting this parameter to None means the whole graph will be kept resident
                                in RAM.
        """
        self._addr_type = addr_type
        self._graph: CfgGraph = CfgGraph()
        self._segment_budget = segment_budget
        self._keys: _IntKeys | _ObjKeys = self._make_keys()
        # edge attributes other than jumpkind/ins_addr/stmt_idx, keyed by (src id, dst id); normally empty
        self._extra_edge_attrs: dict[tuple[int, int], dict] = {}
        # node attributes passed to add_node(); normally empty
        self._node_attrs: dict[K, dict] = {}
        self._cfg_model_ref: weakref.ref[CFGModel] | None = weakref.ref(cfg_model) if cfg_model is not None else None
        self._rtdb = rtdb

        if USE_SPILLING_CFGNODE_DICT:
            effective_cache_limit = cache_limit if cache_limit is not None else 2**31 - 1
        else:
            effective_cache_limit = 2**31 - 1

        self._nodes: SpillingCFGNodeDict = SpillingCFGNodeDict(
            rtdb,
            cfg_model,
            cache_limit=effective_cache_limit,
            db_batch_size=db_batch_size,
        )
        self._spilling_enabled = cache_limit is not None
        self._init_paging()

    def _make_keys(self) -> _IntKeys | _ObjKeys:
        return _IntKeys(self._graph) if self._addr_type == "int" else _ObjKeys(self._graph)

    @property
    def addr_type(self) -> str:
        return self._addr_type

    @addr_type.setter
    def addr_type(self, value: str) -> None:
        if value not in ("int", "block_id", "soot"):
            raise ValueError("addr_type must be 'int', 'block_id', or 'soot'")
        if self._nodes.total_count > 0 or self._graph.number_of_nodes() > 0:
            raise RuntimeError("Cannot change addr_type after nodes have been added")
        self._addr_type = value
        self._keys = self._make_keys()

    #
    # Paging
    #

    def _init_paging(self) -> None:
        """Attach the segment backend when a budget is set."""
        g = self._graph
        if self._segment_budget is None or self._rtdb is None or g.paged:
            return
        g.attach_backend(CFGSegmentStore(self._rtdb), self._segment_budget)

    @property
    def paged(self) -> bool:
        """Whether graph segments are paged to the RuntimeDb."""
        return self._graph.paged

    @property
    def segment_budget(self) -> int | None:
        return self._segment_budget

    @segment_budget.setter
    def segment_budget(self, value: int | None) -> None:
        self._segment_budget = value
        if value is None:
            if self._graph.paged:
                self._graph.detach_backend()
        elif self._graph.paged:
            self._graph.budget_bytes = value
        else:
            self._init_paging()

    def segment_stats(self) -> dict:
        """Segment paging counters: loads, evictions, writebacks, resident/total segments, resident bytes."""
        return self._graph.stats()

    def flush(self) -> None:
        """Compact resident segments and write dirty ones back to the backend (no-op when not paged)."""
        if self._graph.paged:
            self._graph.compact()
            self._graph.flush()

    def _load_graph_blobs(self, header: bytes, blobs: list[bytes]) -> None:
        """Replace the (empty) store with one rebuilt from serialized segment blobs."""
        if self._graph.number_of_nodes() > 0:
            raise RuntimeError("cannot load graph blobs into a non-empty graph")
        self._graph = CfgGraph.from_blobs(header, blobs)
        self._keys.bind(self._graph)
        self._init_paging()

    @property
    def _cfg_model(self) -> CFGModel | None:
        if self._cfg_model_ref is None:
            return None
        return self._cfg_model_ref()

    @_cfg_model.setter
    def _cfg_model(self, value: CFGModel | None) -> None:
        self._cfg_model_ref = weakref.ref(value) if value is not None else None
        self._nodes._cfg_model = value

    def get_node_by_key(self, block_key: K) -> CFGNode:
        """Get a CFGNode by block key."""
        if block_key in self._nodes:
            return self._nodes[block_key]
        raise KeyError(block_key)

    @property
    def node_keys(self) -> Iterator[K]:
        """Get an iterator over all block_keys in the graph."""
        yield from self._nodes

    #
    # id <-> key <-> node helpers
    #

    def _id_of_node(self, node: CFGNode) -> int | None:
        return self._keys.id_of(get_block_key(node))

    def _node_of_id(self, idx: int) -> CFGNode:
        return self.get_node_by_key(self._keys.key_of(idx))

    def _ids_of_nbunch(self, nbunch) -> list[int]:
        nodes = [nbunch] if isinstance(nbunch, CFGNode) else nbunch
        ids = []
        for node in nodes:
            idx = self._keys.id_of(get_block_key(node))
            if idx is not None:
                ids.append(idx)
        return ids

    def _merge_extra(self, src_id: int, dst_id: int, data: dict) -> dict:
        if self._extra_edge_attrs:
            extra = self._extra_edge_attrs.get((src_id, dst_id))
            if extra:
                data.update(extra)
        return data

    def _edge_data(self, src_id: int, dst_id: int) -> dict | None:
        data = self._graph.edge_data(src_id, dst_id)
        if data is None:
            return None
        return self._merge_extra(src_id, dst_id, data)

    def _drop_extra_for_node(self, idx: int) -> None:
        if self._extra_edge_attrs:
            for pair in [p for p in self._extra_edge_attrs if idx in p]:
                del self._extra_edge_attrs[pair]

    #
    # Node operations
    #

    def add_node(self, node: CFGNode, **attr) -> None:
        block_key = get_block_key(node)
        self._nodes[block_key] = node
        self._keys.add(block_key, node.addr)
        if attr:
            self._node_attrs.setdefault(block_key, {}).update(attr)

    def export_serialized_nodes(self) -> list[tuple[K, bytes, bool]]:
        """
        Export every node as the serialized bytes of its CFGNode/CFGENode protobuf message (without the LMDB type
        byte), e.g. for dumping into an angr database.

        Nodes are byte-copied directly out of the LMDB backing store without being deserialized and re-serialized.

        :return: A list of (block key, serialized CFGNode message bytes, copied_from_lmdb) tuples.
        """

        node_dict = self._nodes
        cached = node_dict._data

        # classify keys: byte-copyable (spilled, or cached-and-clean) vs must-materialize (cached-and-dirty)
        copyable_keys: list[K] = []
        materialize: list[K] = []
        for block_key in list(node_dict):
            node = cached.get(block_key)
            if node is not None and node.dirty:
                materialize.append(block_key)
            else:
                copyable_keys.append(block_key)

        result: list[tuple[K, bytes, bool]] = []

        copied_payloads: dict[K, bytes] = {}
        if copyable_keys and node_dict.rtdb is not None and node_dict._nodesdb is not None:
            with node_dict.rtdb.begin_txn(node_dict._nodesdb) as txn:
                for block_key in copyable_keys:
                    payload = txn.get(str(block_key).encode("utf-8"))
                    # only byte-copy plain CFGNode records (type byte 0x00); fall back for missing records or
                    # CFGENode records (0x01) that the consumer parses as CFGNode
                    if payload is not None and payload[0] == 0x00:
                        copied_payloads[block_key] = payload[1:]

        for block_key in copyable_keys:
            payload = copied_payloads.get(block_key)
            if payload is not None:
                result.append((block_key, payload, True))
            else:
                # LMDB record missing or not a plain CFGNode: materialize and serialize
                node = self.get_node_by_key(block_key)
                result.append((block_key, node.serialize_to_cmessage().SerializeToString(), False))

        for block_key in materialize:
            node = cached[block_key]
            result.append((block_key, node.serialize_to_cmessage().SerializeToString(), False))

        return result

    def bulk_import_serialized_nodes(self, items: list[tuple[K, int | SootAddressDescriptor, bytes]]) -> None:
        """
        Bulk-import already-serialized nodes directly into the LMDB backing store as spilled entries, without
        constructing any CFGNode objects.

        :param items:   A list of (block key, node address, serialized node payload) tuples. See
                        SpillingCFGNodeDict.bulk_import_serialized() for the payload format.
        """

        self._nodes.bulk_import_serialized([(block_key, payload) for block_key, _, payload in items])
        add = self._keys.add
        for block_key, addr, _ in items:
            add(block_key, addr)

    def remove_node(self, node: CFGNode) -> None:
        block_key = get_block_key(node)
        if block_key in self._nodes:
            del self._nodes[block_key]
        self._node_attrs.pop(block_key, None)
        idx = self._keys.id_of(block_key)
        if idx is not None:
            self._drop_extra_for_node(idx)
            self._graph.remove_node(idx)
            self._keys.remove(block_key, node.addr)

    def has_node(self, node: CFGNode) -> bool:
        return self._keys.id_of(get_block_key(node)) is not None

    def nodes_by_addr(self, addr: int) -> Iterator[CFGNode]:
        for block_key in self._keys.keys_at(addr):
            yield self.get_node_by_key(block_key)

    def first_key_at_addr(self, addr: int | SootAddressDescriptor) -> K | None:
        """The block key of the first node at the given address, or None."""
        return self._keys.first_key_at(addr)

    def has_node_addr(self, addr: int) -> bool:
        return self._keys.has_addr(addr)

    def node_addrs(self) -> list[int | SootAddressDescriptor]:
        """Distinct addresses of all nodes."""
        return self._keys.addrs()

    def __contains__(self, node: CFGNode) -> bool:
        return self.has_node(node)

    def __len__(self) -> int:
        return self._graph.number_of_nodes()

    def number_of_nodes(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def nodes(self) -> _NodeView:
        """Return a view of nodes supporting len(), iteration, and call with data=True."""
        return _NodeView(self)

    def __iter__(self) -> Iterator[CFGNode]:
        get = self.get_node_by_key
        for block_key in self._keys.block_keys():
            yield get(block_key)

    #
    # Edge operations
    #

    def add_edge(self, src: CFGNode, dst: CFGNode, **attr) -> None:
        src_block_key = get_block_key(src)
        dst_block_key = get_block_key(dst)

        # Always update _nodes with the passed nodes
        # This is needed for node replacement during _shrink_node
        self._nodes[src_block_key] = src
        self._nodes[dst_block_key] = dst

        self.add_edge_by_key(src_block_key, dst_block_key, **attr)

    def add_edge_by_key(self, src_block_key: K, dst_block_key: K, **attr) -> None:
        keys = self._keys
        src_id = keys.id_of(src_block_key)
        if src_id is None:
            src_id = keys.add(src_block_key, block_key_to_addr(src_block_key))
        dst_id = keys.id_of(dst_block_key)
        if dst_id is None:
            dst_id = keys.add(dst_block_key, block_key_to_addr(dst_block_key))

        present = 0
        n_std = 0
        extra: dict | None = None
        jumpkind = ins_addr = stmt_idx = None
        if "jumpkind" in attr:
            n_std += 1
            jumpkind = attr["jumpkind"]
            if jumpkind is None or type(jumpkind) is str:
                present |= PRESENT_JUMPKIND
            else:
                extra = {"jumpkind": jumpkind}
                jumpkind = None
        if "ins_addr" in attr:
            n_std += 1
            ins_addr = attr["ins_addr"]
            if ins_addr is None or (type(ins_addr) is int and 0 <= ins_addr < 2**64):
                present |= PRESENT_INS_ADDR
            else:
                extra = extra or {}
                extra["ins_addr"] = ins_addr
                ins_addr = None
        if "stmt_idx" in attr:
            n_std += 1
            stmt_idx = attr["stmt_idx"]
            if stmt_idx is None or (type(stmt_idx) is int and -(2**31) < stmt_idx < 2**31):
                present |= PRESENT_STMT_IDX
            else:
                extra = extra or {}
                extra["stmt_idx"] = stmt_idx
                stmt_idx = None

        self._graph.add_edge(src_id, dst_id, present, jumpkind, ins_addr, stmt_idx)

        if len(attr) != n_std or extra:
            extra = extra or {}
            extra.update((k, v) for k, v in attr.items() if k not in _STD_EDGE_KEYS)
            self._extra_edge_attrs.setdefault((src_id, dst_id), {}).update(extra)

    def remove_edge(self, src: CFGNode, dst: CFGNode) -> None:
        src_block_key = get_block_key(src)
        dst_block_key = get_block_key(dst)
        self.remove_edge_by_key(src_block_key, dst_block_key)

    def remove_edge_by_key(self, src_block_key: K, dst_block_key: K) -> None:
        src_id = self._keys.id_of(src_block_key)
        dst_id = self._keys.id_of(dst_block_key)
        if src_id is None or dst_id is None or not self._graph.remove_edge(src_id, dst_id):
            raise networkx.NetworkXError(f"The edge {src_block_key}-{dst_block_key} is not in the graph.")
        if self._extra_edge_attrs:
            self._extra_edge_attrs.pop((src_id, dst_id), None)

    def has_edge(self, src: CFGNode, dst: CFGNode) -> bool:
        return self.has_edge_by_key(get_block_key(src), get_block_key(dst))

    def has_edge_by_key(self, src_block_key: K, dst_block_key: K) -> bool:
        src_id = self._keys.id_of(src_block_key)
        if src_id is None:
            return False
        dst_id = self._keys.id_of(dst_block_key)
        return dst_id is not None and self._graph.has_edge(src_id, dst_id)

    def get_edge_data(self, src: CFGNode, dst: CFGNode, default=None) -> dict | None:
        src_id = self._id_of_node(src)
        dst_id = self._id_of_node(dst)
        if src_id is None or dst_id is None:
            return default
        data = self._edge_data(src_id, dst_id)
        return default if data is None else data

    def number_of_edges(self) -> int:
        return self._graph.number_of_edges()

    @property
    def edges(self) -> _EdgeView:
        """Return a view of edges supporting len(), iteration, and call with data=True."""
        return _EdgeView(self)

    #
    # Call destination cache
    #

    @property
    def call_destination_keys(self) -> set[K]:
        """Return the set of block keys that are destinations of call/syscall edges."""
        key_of = self._keys.key_of
        return {key_of(idx) for idx in self._graph.call_destinations()}

    def call_destination_nodes(self) -> Iterator[CFGNode]:
        """Yield CFGNode for each call/syscall destination."""
        for idx in self._graph.call_destinations():
            yield self._node_of_id(idx)

    #
    # Neighbor operations
    #

    def predecessors(self, node: CFGNode) -> Iterator[CFGNode]:
        idx = self._id_of_node(node)
        if idx is None:
            raise networkx.NetworkXError(f"The node {node} is not in the digraph.")
        for pred_id in self._graph.predecessors(idx):
            yield self._node_of_id(pred_id)

    def successors(self, node: CFGNode) -> Iterator[CFGNode]:
        idx = self._id_of_node(node)
        if idx is None:
            raise networkx.NetworkXError(f"The node {node} is not in the digraph.")
        for succ_id in self._graph.successors(idx):
            yield self._node_of_id(succ_id)

    @property
    def in_edges(self) -> _InEdgeView:
        """Return a view of in-edges supporting call, subscript, len, and iteration."""
        return _InEdgeView(self)

    @property
    def out_edges(self) -> _OutEdgeView:
        """Return a view of out-edges supporting call, subscript, len, and iteration."""
        return _OutEdgeView(self)

    @property
    def in_degree(self) -> _InDegreeView:
        """Return a view of in-degrees supporting call, subscript, len, and iteration."""
        return _InDegreeView(self)

    @property
    def out_degree(self) -> _OutDegreeView:
        """Return a view of out-degrees supporting call, subscript, len, and iteration."""
        return _OutDegreeView(self)

    @overload
    def out_edges_by_key(self, key: K, data: Literal[False] = False) -> Generator[tuple[K, K]]: ...
    @overload
    def out_edges_by_key(self, key: K, *, data: Literal[True]) -> Generator[tuple[K, K, dict]]: ...

    def out_edges_by_key(self, key: K, data: bool = False) -> Generator[tuple[K, K] | tuple[K, K, dict]]:
        idx = self._keys.id_of(key)
        if idx is None:
            return
        key_of = self._keys.key_of
        if data:
            for src_id, dst_id, edge_data in self._graph.out_edges_with_data(idx):
                yield key_of(src_id), key_of(dst_id), self._merge_extra(src_id, dst_id, edge_data)
        else:
            for src_id, dst_id in self._graph.out_edges(idx):
                yield key_of(src_id), key_of(dst_id)

    def out_degree_by_key(self, key: K) -> int:
        idx = self._keys.id_of(key)
        return 0 if idx is None else self._graph.out_degree(idx)

    #
    # Adjacency access
    #

    def __getitem__(self, node: CFGNode) -> _AdjacencyDict:
        idx = self._id_of_node(node)
        if idx is None:
            raise KeyError(node)
        return _AdjacencyDict(self, idx)

    #
    # Graph operations
    #

    def copy(self) -> SpillingCFG:
        new_graph = SpillingCFG(
            rtdb=self._rtdb,
            cfg_model=self._cfg_model,
            cache_limit=self._nodes._cache_limit if self._spilling_enabled else None,
            db_batch_size=self._nodes.db_batch_size,
            addr_type=self._addr_type,
            segment_budget=self._segment_budget,
        )

        new_graph._nodes = self._nodes.copy()
        new_graph._spilling_enabled = self._spilling_enabled
        new_graph._graph = self._graph.copy()
        new_graph._keys = self._keys.copy(new_graph._graph)
        new_graph._extra_edge_attrs = {k: dict(v) for k, v in self._extra_edge_attrs.items()}
        new_graph._node_attrs = {k: dict(v) for k, v in self._node_attrs.items()}
        new_graph._init_paging()

        return new_graph

    def subgraph(self, nodes) -> networkx.DiGraph:
        """
        Return a subgraph as a regular networkx DiGraph with CFGNode instances.
        This is useful for algorithms that need a pure networkx graph.
        """
        ids = {}
        for node in nodes:
            idx = self._id_of_node(node)
            if idx is not None:
                ids[idx] = node

        result = networkx.DiGraph()
        for node in ids.values():
            result.add_node(node)
        for src_id, src in ids.items():
            for _, dst_id, data in self._graph.out_edges_with_data(src_id):
                if dst_id in ids:
                    result.add_edge(src, ids[dst_id], **self._merge_extra(src_id, dst_id, data))

        return result

    def to_networkx(self) -> networkx.DiGraph:
        """
        Convert to a pure networkx DiGraph with CFGNode instances as nodes.
        Warning: This loads all spilled nodes into memory.
        """
        result = networkx.DiGraph()
        for node in self.nodes():
            result.add_node(node)
        for src, dst, data in self.edges(data=True):
            result.add_edge(src, dst, **data)
        return result

    def from_networkx(self, nx_graph: networkx.DiGraph) -> None:
        """
        Load graph structure from a networkx DiGraph with CFGNode instances as nodes.
        """
        self._graph.clear()
        self._keys.clear()
        self._extra_edge_attrs.clear()
        self._node_attrs.clear()
        self._nodes.clear()

        for node in nx_graph.nodes():
            self.add_node(node)

        for src, dst, data in nx_graph.edges(data=True):
            self.add_edge(src, dst, **data)

    #
    # Spilling control
    #

    @property
    def cache_limit(self) -> int | None:
        if self._spilling_enabled:
            return self._nodes.cache_limit
        return None

    @cache_limit.setter
    def cache_limit(self, value: int | None) -> None:
        if value is not None:
            self._nodes.cache_limit = value
            self._spilling_enabled = True
        else:
            # Set to a very large value to effectively disable spilling
            self._nodes.cache_limit = 2**31 - 1
            self._spilling_enabled = False

    @property
    def db_batch_size(self) -> int:
        return self._nodes.db_batch_size

    @db_batch_size.setter
    def db_batch_size(self, value: int) -> None:
        self._nodes.db_batch_size = value

    @property
    def cached_count(self) -> int:
        return self._nodes.cached_count

    @property
    def spilled_count(self) -> int:
        return self._nodes.spilled_count

    def load_all_spilled(self) -> None:
        self._nodes.load_all_spilled()

    def evict_all_cached(self) -> None:
        self._nodes.evict_all_cached()

    def set_rtdb(self, rtdb: RuntimeDb | None) -> None:
        """
        (Re-)attach a RuntimeDb to this graph and its node store. This is used after unpickling (rtdb references are
        not preserved across pickling) so that node spilling works again.
        """
        self._rtdb = rtdb
        self._nodes.rtdb = rtdb
        if rtdb is not None:
            self._init_paging()

    #
    # Pickling
    #

    def __getstate__(self):
        self._nodes.load_all_spilled()
        nodes_state = self._nodes.__getstate__()

        return {
            "graph": self._graph,
            "keys": self._keys if isinstance(self._keys, _ObjKeys) else None,
            "extra_edge_attrs": self._extra_edge_attrs,
            "node_attrs": self._node_attrs,
            "nodes": nodes_state,
            "spilling_enabled": self._spilling_enabled,
            "db_batch_size": self._nodes.db_batch_size,
            "addr_type": self._addr_type,
            "segment_budget": self._segment_budget,
        }

    def __setstate__(self, state: dict):
        self._addr_type = state["addr_type"]
        self._graph = state["graph"]
        keys = state["keys"]
        if keys is None:
            self._keys = _IntKeys(self._graph)
        else:
            keys.bind(self._graph)
            self._keys = keys
        self._extra_edge_attrs = state["extra_edge_attrs"]
        self._node_attrs = state["node_attrs"]
        self._spilling_enabled = state["spilling_enabled"]
        self._segment_budget = state["segment_budget"]
        self._cfg_model_ref = None
        self._rtdb = None

        nodes_state = state["nodes"]
        self._nodes = SpillingCFGNodeDict.__new__(SpillingCFGNodeDict)
        self._nodes.__setstate__(nodes_state)
