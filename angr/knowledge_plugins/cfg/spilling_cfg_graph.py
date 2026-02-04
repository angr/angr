"""
Spilling CFG Graph implementation with LRU caching and LMDB persistence.

This module provides SpillingCFGNodeDict and SpillingCFGGraph classes that implement
disk-backed storage for CFGNode instances, following the SpillingFunctionDict pattern.
"""
from __future__ import annotations

import pickle
import logging
import threading
import weakref
from collections import OrderedDict
from collections.abc import Iterator
from typing import TYPE_CHECKING, TypeVar

import lmdb
import networkx

from .cfg_node import CFGNode

if TYPE_CHECKING:
    from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb
    from .cfg_model import CFGModel

l = logging.getLogger(name=__name__)

K = TypeVar("K", bound=int)


class SpillingCFGNodeDict:
    """
    A dict-like container for CFGNode instances with LRU caching and LMDB spilling.

    This class keeps only the most recently accessed N nodes in memory, spilling others
    to an LMDB database on disk. This allows working with CFGs that have more nodes than
    can fit in memory.

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
        cache_limit: int = 10000,
        db_batch_size: int = 1000,
    ):
        self._data: dict[int, CFGNode] = {}
        self._cache_limit: int = cache_limit
        self._db_batch_size: int = max(cache_limit - 1, db_batch_size) if cache_limit > 0 else db_batch_size

        self.rtdb: RuntimeDb | None = rtdb
        self._cfg_model_ref: weakref.ref[CFGModel] | None = weakref.ref(cfg_model) if cfg_model is not None else None

        self._lru_order: OrderedDict[int, None] = OrderedDict()
        self._spilled_keys: set[int] = set()

        self._nodesdb = None
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

    def __getitem__(self, block_id: int) -> CFGNode:
        # First try to get from in-memory cache
        if block_id in self._data:
            self._touch(block_id)
            return self._data[block_id]

        # Try to load from LMDB if spilled
        if block_id in self._spilled_keys:
            node = self._load_from_lmdb(block_id)
            if node is not None:
                return node

        raise KeyError(block_id)

    def __setitem__(self, block_id: int, node: CFGNode) -> None:
        self._data[block_id] = node
        self._on_node_stored(block_id)

    def __delitem__(self, block_id: int) -> None:
        # Remove from in-memory cache if present
        if block_id in self._data:
            del self._data[block_id]
        # Remove from spilled set if present
        self._spilled_keys.discard(block_id)
        # Remove from LRU order
        if block_id in self._lru_order:
            del self._lru_order[block_id]

    def __contains__(self, block_id: object) -> bool:
        return block_id in self._data or block_id in self._spilled_keys

    def __len__(self) -> int:
        return len(self._data) + len(self._spilled_keys)

    def __iter__(self) -> Iterator[int]:
        # Iterate over all block_ids (cached + spilled)
        yield from self._data.keys()
        yield from self._spilled_keys

    def get(self, block_id: int, default: CFGNode | None = None) -> CFGNode | None:
        try:
            return self[block_id]
        except KeyError:
            return default

    def keys(self) -> Iterator[int]:
        return iter(self)

    def values(self) -> Iterator[CFGNode]:
        for block_id in self:
            yield self[block_id]

    def items(self) -> Iterator[tuple[int, CFGNode]]:
        for block_id in self:
            yield block_id, self[block_id]

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
        for block_id, node in self._data.items():
            new_dict._data[block_id] = node.copy()
            new_dict._lru_order[block_id] = None

        # Copy spilled data from LMDB
        if self._spilled_keys and self._nodesdb is not None and self.rtdb is not None:
            new_dict._init_lmdb()
            with (
                self.rtdb.begin_txn(self._nodesdb) as src_txn,
                self.rtdb.begin_txn(new_dict._nodesdb, write=True) as dst_txn,
            ):
                for block_id in self._spilled_keys:
                    key = str(block_id).encode("utf-8")
                    value = src_txn.get(key)
                    if value is not None:
                        dst_txn.put(key, value)
                        new_dict._spilled_keys.add(block_id)

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
        if self.cached_count > value:
            self._evict_lru()

    @property
    def cached_count(self) -> int:
        return len(self._data)

    @property
    def spilled_count(self) -> int:
        return len(self._spilled_keys)

    @property
    def total_count(self) -> int:
        return len(self._data) + len(self._spilled_keys)

    def is_cached(self, block_id: int) -> bool:
        return block_id in self._data

    #
    # LRU Cache Management
    #

    def _touch(self, block_id: int) -> None:
        if block_id in self._lru_order:
            self._lru_order.move_to_end(block_id)
        else:
            self._lru_order[block_id] = None

    def _on_node_stored(self, block_id: int) -> None:
        self._touch(block_id)
        self._spilled_keys.discard(block_id)

        if self._eviction_enabled and self._cache_limit is not None and self.cached_count > self._cache_limit:
            self._evict_lru()

    def _evict_lru(self) -> bool:
        with self._db_store_lock:
            evicted_any = False
            while self.cached_count > self._cache_limit:
                # Evict enough to get below the limit, in batches
                to_evict = self.cached_count - self._cache_limit
                batch_size = min(self._db_batch_size, to_evict)
                if self._evict_n(batch_size) == 0:
                    break
                evicted_any = True
            return evicted_any

    def _evict_n(self, n: int) -> int:
        if not self._lru_order:
            return 0

        evicted = 0
        nodes_to_evict = []
        for lru_block_id in list(self._lru_order):
            if evicted >= n:
                break

            if lru_block_id not in self._data:
                self._lru_order.pop(lru_block_id)
                continue

            node = self._data[lru_block_id]
            nodes_to_evict.append((lru_block_id, node))

            del self._data[lru_block_id]
            del self._lru_order[lru_block_id]
            self._spilled_keys.add(lru_block_id)
            evicted += 1

        if nodes_to_evict:
            self._save_to_lmdb(nodes_to_evict)

        return evicted

    #
    # LMDB Management
    #

    def _init_lmdb(self) -> None:
        if self._nodesdb is None and self.rtdb is not None:
            self._nodesdb = self.rtdb.get_db("cfgnodes")
            l.debug("Initialized CFGNode LMDB cache.")

    def _cleanup_lmdb(self) -> None:
        if self._nodesdb is not None and self.rtdb is not None:
            self.rtdb.drop_db(self._nodesdb)
            self._nodesdb = None

    def _save_to_lmdb(self, nodes: list[tuple[int, CFGNode]]) -> None:
        if self.rtdb is None:
            return

        self._init_lmdb()

        while True:
            try:
                with self.rtdb.begin_txn(self._nodesdb, write=True) as txn:
                    for block_id, node in nodes:
                        # Serialize using pickle with __getstate__
                        state = node.__getstate__()
                        key = str(block_id).encode("utf-8")
                        txn.put(key, pickle.dumps(state))
                break
            except lmdb.MapFullError:
                self.rtdb.increase_lmdb_map_size()

    def _load_from_lmdb(self, block_id: int) -> CFGNode | None:
        if self._nodesdb is None or self.rtdb is None:
            return None

        with self._db_load_lock:
            return self._load_from_lmdb_core(block_id)

    def _load_from_lmdb_core(self, block_id: int) -> CFGNode | None:
        if self._loading_from_lmdb:
            raise RuntimeError("Recursive loading from LMDB detected. This is a bug.")

        self._loading_from_lmdb = True

        try:
            key = str(block_id).encode("utf-8")

            with self.rtdb.begin_txn(self._nodesdb) as txn:
                value = txn.get(key)
                if value is None:
                    return None

                state = pickle.loads(value)

                # Create node using __setstate__
                node = object.__new__(CFGNode)
                node.__setstate__(state)

                # Restore cfg_model reference
                if self._cfg_model is not None:
                    node._cfg_model = self._cfg_model

            # Remove from spilled set and add to cache
            self._spilled_keys.discard(block_id)
            self._data[block_id] = node
            self._on_node_stored(block_id)

            return node
        finally:
            self._loading_from_lmdb = False

            if self._eviction_enabled and self._cache_limit is not None and self.cached_count > self._cache_limit:
                self._evict_lru()

    def load_all_spilled(self) -> None:
        if not self._spilled_keys:
            return

        old_eviction_state = self._eviction_enabled
        self._eviction_enabled = False

        try:
            block_ids_to_load = list(self._spilled_keys)
            for block_id in block_ids_to_load:
                self._load_from_lmdb(block_id)
        finally:
            self._eviction_enabled = old_eviction_state

    def evict_all_cached(self) -> None:
        if self.cached_count == 0:
            return
        self._evict_n(self.cached_count)

    #
    # Pickling
    #

    def __getstate__(self):
        # Load all spilled nodes before pickling
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
            self[k] = v


class _AdjacencyDict:
    """Helper class to support graph[src][dst] access pattern."""

    def __init__(self, graph: SpillingCFGGraph, src_block_id: int):
        self._graph = graph
        self._src_block_id = src_block_id

    def __getitem__(self, dst_node: CFGNode) -> dict:
        dst_block_id = self._graph._get_block_id(dst_node)
        return self._graph._graph[self._src_block_id][dst_block_id]

    def __contains__(self, dst_node: CFGNode) -> bool:
        dst_block_id = self._graph._get_block_id(dst_node)
        return dst_block_id in self._graph._graph[self._src_block_id]

    def keys(self) -> Iterator[CFGNode]:
        for dst_block_id in self._graph._graph[self._src_block_id]:
            yield self._graph._get_node_by_id(dst_block_id)

    def values(self) -> Iterator[dict]:
        for dst_block_id in self._graph._graph[self._src_block_id]:
            yield self._graph._graph[self._src_block_id][dst_block_id]

    def items(self) -> Iterator[tuple[CFGNode, dict]]:
        for dst_block_id in self._graph._graph[self._src_block_id]:
            yield self._graph._get_node_by_id(dst_block_id), self._graph._graph[self._src_block_id][dst_block_id]

    def __iter__(self) -> Iterator[CFGNode]:
        return self.keys()


class _NodeView:
    """View over graph nodes supporting len(), iteration, and call with data=True."""

    def __init__(self, graph: SpillingCFGGraph):
        self._graph = graph

    def __len__(self) -> int:
        return len(self._graph._graph)

    def __iter__(self) -> Iterator[CFGNode]:
        for block_id in self._graph._graph.nodes():
            yield self._graph._get_node_by_id(block_id)

    def __call__(self, data: bool = False) -> Iterator[CFGNode] | Iterator[tuple[CFGNode, dict]]:
        if data:
            for block_id, node_data in self._graph._graph.nodes(data=True):
                yield self._graph._get_node_by_id(block_id), node_data
        else:
            yield from self

    def __contains__(self, node: CFGNode) -> bool:
        return self._graph.has_node(node)


class _EdgeView:
    """View over graph edges supporting len(), iteration, and call with data=True."""

    def __init__(self, graph: SpillingCFGGraph):
        self._graph = graph

    def __len__(self) -> int:
        return self._graph._graph.number_of_edges()

    def __iter__(self) -> Iterator[tuple[CFGNode, CFGNode]]:
        for src_id, dst_id in self._graph._graph.edges():
            yield self._graph._get_node_by_id(src_id), self._graph._get_node_by_id(dst_id)

    def __call__(
        self, data: bool = False
    ) -> Iterator[tuple[CFGNode, CFGNode]] | Iterator[tuple[CFGNode, CFGNode, dict]]:
        if data:
            for src_id, dst_id, edge_data in self._graph._graph.edges(data=True):
                yield self._graph._get_node_by_id(src_id), self._graph._get_node_by_id(dst_id), edge_data
        else:
            yield from self


class SpillingCFGGraph:
    """
    A graph wrapper that stores CFGNode instances in a spilling dict while keeping
    only integer keys in the underlying networkx graph.

    This provides a networkx-compatible interface while supporting disk-backed
    storage for large CFGs.
    """

    def __init__(
        self,
        rtdb: RuntimeDb | None = None,
        cfg_model: CFGModel | None = None,
        cache_limit: int | None = None,
        db_batch_size: int = 1000,
    ):
        self._graph: networkx.DiGraph = networkx.DiGraph()
        self._cfg_model_ref: weakref.ref[CFGModel] | None = weakref.ref(cfg_model) if cfg_model is not None else None
        self._rtdb = rtdb
        self._db_batch_size = db_batch_size

        # Always use SpillingCFGNodeDict, but with a very large cache when spilling is disabled
        effective_cache_limit = cache_limit if cache_limit is not None else 2**31 - 1
        self._nodes: SpillingCFGNodeDict = SpillingCFGNodeDict(
            rtdb,
            cfg_model,
            cache_limit=effective_cache_limit,
            db_batch_size=db_batch_size,
        )
        self._spilling_enabled = cache_limit is not None

    @property
    def _cfg_model(self) -> CFGModel | None:
        if self._cfg_model_ref is None:
            return None
        return self._cfg_model_ref()

    @_cfg_model.setter
    def _cfg_model(self, value: CFGModel | None) -> None:
        self._cfg_model_ref = weakref.ref(value) if value is not None else None
        self._nodes._cfg_model = value

    def _get_block_id(self, node: CFGNode) -> int:
        block_id = node.block_id
        if block_id is None:
            block_id = node.addr
        return block_id

    def _get_node_by_id(self, block_id: int) -> CFGNode:
        """Get a CFGNode by block_id, with fallback to graph node data."""
        # First try the nodes dict (handles spilling)
        if block_id in self._nodes:
            return self._nodes[block_id]
        # Fallback to graph node data (for nodes removed from _nodes but still in graph)
        if block_id in self._graph:
            node_data = self._graph.nodes[block_id]
            if "_node" in node_data:
                return node_data["_node"]
        raise KeyError(block_id)

    #
    # Node operations
    #

    def add_node(self, node: CFGNode, **attr) -> None:
        block_id = self._get_block_id(node)
        self._nodes[block_id] = node
        # Store node reference in graph data for fallback lookup
        self._graph.add_node(block_id, _node=node, **attr)

    def remove_node(self, node: CFGNode) -> None:
        block_id = self._get_block_id(node)
        # Check if the stored node is the same as the one being removed
        # If a different node with the same block_id exists (replacement happened),
        # don't remove from the graph to preserve edges
        should_remove_from_graph = True
        if block_id in self._nodes:
            stored_node = self._nodes[block_id]
            if stored_node is not node:
                # A replacement happened - don't remove from graph
                should_remove_from_graph = False
            else:
                del self._nodes[block_id]

        if should_remove_from_graph and block_id in self._graph:
            self._graph.remove_node(block_id)

    def has_node(self, node: CFGNode) -> bool:
        block_id = self._get_block_id(node)
        return block_id in self._graph

    def __contains__(self, node: CFGNode) -> bool:
        return self.has_node(node)

    def __len__(self) -> int:
        return len(self._graph)

    def number_of_nodes(self) -> int:
        return len(self._graph)

    @property
    def nodes(self) -> _NodeView:
        """Return a view of nodes supporting len(), iteration, and call with data=True."""
        return _NodeView(self)

    def __iter__(self) -> Iterator[CFGNode]:
        for block_id in self._graph:
            yield self._get_node_by_id(block_id)

    #
    # Edge operations
    #

    def add_edge(self, src: CFGNode, dst: CFGNode, **attr) -> None:
        src_block_id = self._get_block_id(src)
        dst_block_id = self._get_block_id(dst)

        # Always update _nodes with the passed nodes
        # This is needed for node replacement during _shrink_node
        self._nodes[src_block_id] = src
        self._nodes[dst_block_id] = dst

        # Ensure nodes exist in the graph structure
        if src_block_id not in self._graph:
            self._graph.add_node(src_block_id, _node=src)

        if dst_block_id not in self._graph:
            self._graph.add_node(dst_block_id, _node=dst)

        self._graph.add_edge(src_block_id, dst_block_id, **attr)

    def remove_edge(self, src: CFGNode, dst: CFGNode) -> None:
        src_block_id = self._get_block_id(src)
        dst_block_id = self._get_block_id(dst)
        self._graph.remove_edge(src_block_id, dst_block_id)

    def has_edge(self, src: CFGNode, dst: CFGNode) -> bool:
        src_block_id = self._get_block_id(src)
        dst_block_id = self._get_block_id(dst)
        return self._graph.has_edge(src_block_id, dst_block_id)

    def get_edge_data(self, src: CFGNode, dst: CFGNode, default=None) -> dict | None:
        src_block_id = self._get_block_id(src)
        dst_block_id = self._get_block_id(dst)
        return self._graph.get_edge_data(src_block_id, dst_block_id, default)

    def number_of_edges(self) -> int:
        return self._graph.number_of_edges()

    @property
    def edges(self) -> _EdgeView:
        """Return a view of edges supporting len(), iteration, and call with data=True."""
        return _EdgeView(self)

    #
    # Neighbor operations
    #

    def predecessors(self, node: CFGNode) -> Iterator[CFGNode]:
        block_id = self._get_block_id(node)
        for pred_id in self._graph.predecessors(block_id):
            yield self._get_node_by_id(pred_id)

    def successors(self, node: CFGNode) -> Iterator[CFGNode]:
        block_id = self._get_block_id(node)
        for succ_id in self._graph.successors(block_id):
            yield self._get_node_by_id(succ_id)

    def in_edges(
        self, nbunch=None, data: bool = False
    ) -> list[tuple[CFGNode, CFGNode]] | list[tuple[CFGNode, CFGNode, dict]]:
        if nbunch is not None:
            if isinstance(nbunch, CFGNode):
                nbunch = [self._get_block_id(nbunch)]
            else:
                nbunch = [self._get_block_id(n) for n in nbunch]

        if data:
            return [
                (self._get_node_by_id(src_id), self._get_node_by_id(dst_id), edge_data)
                for src_id, dst_id, edge_data in self._graph.in_edges(nbunch, data=True)
            ]
        else:
            return [
                (self._get_node_by_id(src_id), self._get_node_by_id(dst_id))
                for src_id, dst_id in self._graph.in_edges(nbunch)
            ]

    def out_edges(
        self, nbunch=None, data: bool = False
    ) -> list[tuple[CFGNode, CFGNode]] | list[tuple[CFGNode, CFGNode, dict]]:
        if nbunch is not None:
            if isinstance(nbunch, CFGNode):
                nbunch = [self._get_block_id(nbunch)]
            else:
                nbunch = [self._get_block_id(n) for n in nbunch]

        if data:
            return [
                (self._get_node_by_id(src_id), self._get_node_by_id(dst_id), edge_data)
                for src_id, dst_id, edge_data in self._graph.out_edges(nbunch, data=True)
            ]
        else:
            return [
                (self._get_node_by_id(src_id), self._get_node_by_id(dst_id))
                for src_id, dst_id in self._graph.out_edges(nbunch)
            ]

    def in_degree(self, node: CFGNode | None = None):
        if node is None:
            return self._graph.in_degree()
        block_id = self._get_block_id(node)
        # Return 0 for nodes not in the graph (they have no edges)
        if block_id not in self._graph:
            return 0
        return self._graph.in_degree(block_id)

    def out_degree(self, node: CFGNode | None = None):
        if node is None:
            return self._graph.out_degree()
        block_id = self._get_block_id(node)
        # Return 0 for nodes not in the graph (they have no edges)
        if block_id not in self._graph:
            return 0
        return self._graph.out_degree(block_id)

    #
    # Adjacency access
    #

    def __getitem__(self, node: CFGNode) -> _AdjacencyDict:
        block_id = self._get_block_id(node)
        if block_id not in self._graph:
            raise KeyError(node)
        return _AdjacencyDict(self, block_id)

    #
    # Graph operations
    #

    def reverse(self, copy: bool = True) -> SpillingCFGGraph:
        if not copy:
            raise NotImplementedError("In-place reverse not supported for SpillingCFGGraph")

        new_graph = SpillingCFGGraph(
            rtdb=self._rtdb,
            cfg_model=self._cfg_model,
            cache_limit=self._nodes._cache_limit if self._spilling_enabled else None,
            db_batch_size=self._db_batch_size,
        )

        # Copy nodes
        new_graph._nodes = self._nodes.copy()
        new_graph._spilling_enabled = self._spilling_enabled

        # Reverse edges
        new_graph._graph = self._graph.reverse(copy=True)

        return new_graph

    def copy(self) -> SpillingCFGGraph:
        new_graph = SpillingCFGGraph(
            rtdb=self._rtdb,
            cfg_model=self._cfg_model,
            cache_limit=self._nodes._cache_limit if self._spilling_enabled else None,
            db_batch_size=self._db_batch_size,
        )

        new_graph._nodes = self._nodes.copy()
        new_graph._spilling_enabled = self._spilling_enabled
        new_graph._graph = self._graph.copy()

        return new_graph

    def subgraph(self, nodes) -> networkx.DiGraph:
        """
        Return a subgraph as a regular networkx DiGraph with CFGNode instances.
        This is useful for algorithms that need a pure networkx graph.
        """
        block_ids = [self._get_block_id(n) for n in nodes]
        sub = self._graph.subgraph(block_ids)

        # Convert to CFGNode-based graph
        result = networkx.DiGraph()
        for block_id in sub.nodes():
            result.add_node(self._get_node_by_id(block_id))
        for src_id, dst_id, data in sub.edges(data=True):
            result.add_edge(self._get_node_by_id(src_id), self._get_node_by_id(dst_id), **data)

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
    def cached_count(self) -> int:
        return self._nodes.cached_count

    @property
    def spilled_count(self) -> int:
        return self._nodes.spilled_count

    def load_all_spilled(self) -> None:
        self._nodes.load_all_spilled()

    def evict_all_cached(self) -> None:
        self._nodes.evict_all_cached()

    #
    # Pickling
    #

    def __getstate__(self):
        self._nodes.load_all_spilled()
        nodes_state = self._nodes.__getstate__()

        return {
            "graph": self._graph,
            "nodes": nodes_state,
            "spilling_enabled": self._spilling_enabled,
            "db_batch_size": self._db_batch_size,
        }

    def __setstate__(self, state: dict):
        self._graph = state["graph"]
        self._spilling_enabled = state["spilling_enabled"]
        self._cfg_model_ref = None
        self._rtdb = None
        self._db_batch_size = state.get("db_batch_size", 1000)

        nodes_state = state["nodes"]
        self._nodes = SpillingCFGNodeDict.__new__(SpillingCFGNodeDict)
        self._nodes.__setstate__(nodes_state)
