# pylint:disable=protected-access
"""
CFG graph storage: the graph structure, edge attributes and the CFGNode records of integer-keyed graphs live in the
packed Rust store CfgGraph (paged to the RuntimeDb in address-window segments); Python CFGNode objects are views over
the records. Graphs keyed by BlockID (CFGEmulated) or Soot addresses keep plain Python node objects.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
import weakref
from collections import defaultdict
from collections.abc import Generator, Iterator
from typing import TYPE_CHECKING, Literal, overload

import lmdb
import networkx
from archinfo.arch_soot import SootAddressDescriptor

from angr.rustylib.cfg_graph import PRESENT_INS_ADDR, PRESENT_JUMPKIND, PRESENT_STMT_IDX, CfgGraph

from .block_id import BlockID
from .cfg_node import CFGENode, CFGNode, bytes_mode_of
from .types import CFG_ADDR_TYPES, CFGENODE_K, CFGNODE_K, SOOTNODE_K, K

if TYPE_CHECKING:
    from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb

    from .cfg_model import CFGModel

l = logging.getLogger(name=__name__)


def _is_u64(addr: object) -> bool:
    # check if addr is an int and if it's within the u64 range
    return isinstance(addr, int) and 0 <= addr < (1 << 64)


class _IntKeys:
    """
    Key table for ``addr_type == "int"``: block keys are ``(addr, size)``, the Rust store is the table, and nodes are
    CFGNode views over the store's records. A view cache (weak references plus a ring of strong references) makes
    repeated lookups of a node return the same object.
    """

    __slots__ = ("_cache", "_g", "_gone_cb", "_ring", "_ring_pos")

    RING_SIZE = 4096

    def __init__(self, graph: CfgGraph):
        self._g = graph
        self._cache: dict[int, weakref.KeyedRef] = {}
        # one bound method shared by every KeyedRef
        self._gone_cb = self._gone
        self._ring: list[CFGNode | None] = [None] * self.RING_SIZE
        self._ring_pos = 0

    def bind(self, graph: CfgGraph) -> None:
        self._g = graph

    #
    # View cache
    #

    def _cached(self, idx: int) -> CFGNode | None:
        ref = self._cache.get(idx)
        return None if ref is None else ref()

    def _put(self, idx: int, node: CFGNode) -> None:
        self._cache[idx] = weakref.KeyedRef(node, self._gone_cb, idx)
        self._ring[self._ring_pos] = node
        self._ring_pos = (self._ring_pos + 1) % self.RING_SIZE

    def _gone(self, ref: weakref.KeyedRef) -> None:
        if self._cache.get(ref.key) is ref:
            del self._cache[ref.key]

    def _drop(self, idx: int) -> CFGNode | None:
        ref = self._cache.pop(idx, None)
        return None if ref is None else ref()

    def detach_all(self) -> None:
        """Snapshot every live view onto its object; the records may be removed or replaced afterwards."""
        for ref in list(self._cache.values()):
            node = ref()
            if node is not None:
                node._detach()
        self._cache.clear()
        self._ring = [None] * self.RING_SIZE
        self._ring_pos = 0

    #
    # Nodes
    #

    def node_of_id(self, idx: int, model: CFGModel | None, fields: tuple | None = None) -> CFGNode:
        node = self._cached(idx)
        if node is not None:
            return node
        addr, size, simprocedure_name = self._g.node_view(idx) if fields is None else fields
        node = CFGNode._view(self._g, idx, addr, size, simprocedure_name, model)
        self._put(idx, node)
        return node

    def add_node(self, node: CFGNode, model: CFGModel | None) -> int:  # pylint:disable=unused-argument
        """Insert (or overwrite) the record of a node and attach the node to it; returns its id."""
        g = self._g
        if node._store is g:
            return node._id  # type:ignore[return-value]
        if type(node) is not CFGNode:
            # views are recreated as plain CFGNodes
            raise TypeError(f"an integer-keyed graph only holds CFGNode instances, not {type(node).__name__}")
        addr = node.addr
        if not _is_u64(addr):
            raise TypeError(f"node address {addr!r} is not an integer address")
        block_id = node.block_id
        if block_id is not None and block_id != addr:
            raise TypeError(f"block key {get_block_key(node)!r} does not start with the node address {addr!r}")
        fields = node._record_fields()
        existing = g.find_node(addr, node.size)
        if existing is not None:
            # snapshot the current view before its record is overwritten
            old = self._drop(existing)
            if old is not None:
                old._detach()
        idx = g.add_node_rec(addr, node.size, *fields)[0]
        if node._store is None:
            node._attach(g, idx)
            self._put(idx, node)
        return idx

    def remove(self, idx: int) -> None:
        old = self._drop(idx)
        if old is not None:
            old._detach()
        self._g.remove_node(idx)

    def iter_nodes(self, model: CFGModel | None) -> Iterator[CFGNode]:
        node_of_id = self.node_of_id
        for idx, addr, size, simprocedure_name in self._g.node_views():
            yield node_of_id(idx, model, (addr, size, simprocedure_name))

    def prefetch(self) -> dict[int, tuple]:
        """`id -> (addr, size, simprocedure_name)` of every node, for bulk view creation."""
        return {idx: (addr, size, sp) for idx, addr, size, sp in self._g.node_views()}

    def clear(self) -> None:
        self.detach_all()

    def copy(self, graph: CfgGraph) -> _IntKeys:
        return _IntKeys(graph)

    #
    # Keys
    #

    def id_of(self, key: K) -> int | None:
        if not _is_u64(key[0]):  # type:ignore[index]
            return None
        return self._g.find_node(key[0], key[1])  # type:ignore[index]

    def add_key(self, key: K) -> int:
        """Insert a node by key only (default record fields)."""
        if not _is_u64(key[0]):  # type:ignore[index]
            raise TypeError(f"block key {key!r} does not start with an integer address")
        return self._g.add_node(key[0], key[1])[0]  # type:ignore[index]

    def key_of(self, idx: int) -> K:
        return self._g.node_key(idx)

    def block_keys(self) -> list[K]:
        return self._g.node_keys()  # type:ignore[return-value]

    def ids_at(self, addr: int | SootAddressDescriptor) -> list[int]:
        if not _is_u64(addr):
            return []
        return self._g.nodes_at_addr(addr)  # type:ignore[arg-type]

    def keys_at(self, addr: int | SootAddressDescriptor) -> list[K]:
        g = self._g
        return [g.node_key(i) for i in self.ids_at(addr)]

    def first_key_at(self, addr: int | SootAddressDescriptor) -> K | None:
        if not _is_u64(addr):
            return None
        idx = self._g.first_node_at_addr(addr)  # type:ignore[arg-type]
        return None if idx is None else self._g.node_key(idx)

    def has_addr(self, addr: int | SootAddressDescriptor) -> bool:
        if not _is_u64(addr):
            return False
        return self._g.has_addr(addr)  # type:ignore[arg-type]

    def addrs(self) -> list[int | SootAddressDescriptor]:
        return self._g.addrs()  # type:ignore[return-value]


class _ObjKeys:
    """
    Key table for ``addr_type in ("block_id", "soot")``: block keys are interned, the Rust store sees the opaque key
    ``(id, 0)``, and the node objects are held here (they are never views).
    """

    __slots__ = ("_g", "_id_to_key", "_key_to_id", "_keys_by_addr", "_next", "_objs")

    def __init__(self, graph: CfgGraph):
        self._g = graph
        self._key_to_id: dict[K, int] = {}
        self._id_to_key: dict[int, K] = {}
        self._keys_by_addr: dict[int | SootAddressDescriptor, set[K]] = defaultdict(set)
        self._objs: dict[int, CFGNode] = {}
        # opaque "address" handed to the store; node ids may be reused after removals, this never is
        self._next = 0

    def bind(self, graph: CfgGraph) -> None:
        self._g = graph

    #
    # Nodes
    #

    def node_of_id(self, idx: int, model: CFGModel | None, fields: tuple | None = None) -> CFGNode:  # pylint:disable=unused-argument
        return self._objs[idx]

    def add_node(self, node: CFGNode, model: CFGModel | None) -> int:  # pylint:disable=unused-argument
        idx = self.add_key(get_block_key(node), node.addr)
        self._objs[idx] = node
        return idx

    def remove(self, idx: int) -> None:
        key = self._id_to_key.pop(idx)
        del self._key_to_id[key]
        node = self._objs.pop(idx)
        keys = self._keys_by_addr.get(node.addr)
        if keys is not None:
            keys.discard(key)
            if not keys:
                del self._keys_by_addr[node.addr]
        self._g.remove_node(idx)

    def iter_nodes(self, model: CFGModel | None) -> Iterator[CFGNode]:  # pylint:disable=unused-argument
        objs = self._objs
        for idx in self._g.nodes():
            yield objs[idx]

    def prefetch(self) -> None:
        return None

    def clear(self) -> None:
        self._key_to_id.clear()
        self._id_to_key.clear()
        self._keys_by_addr.clear()
        self._objs.clear()
        self._next = 0

    def copy(self, graph: CfgGraph) -> _ObjKeys:
        new = _ObjKeys(graph)
        new._key_to_id = dict(self._key_to_id)
        new._id_to_key = dict(self._id_to_key)
        new._objs = {idx: node.copy() for idx, node in self._objs.items()}
        new._next = self._next
        for addr, keys in self._keys_by_addr.items():
            new._keys_by_addr[addr] = set(keys)
        return new

    #
    # Keys
    #

    def id_of(self, key: K) -> int | None:
        return self._key_to_id.get(key)

    def add_key(self, key: K, addr: int | SootAddressDescriptor | None = None) -> int:
        idx = self._key_to_id.get(key)
        if idx is not None:
            return idx
        if addr is None:
            addr = block_key_to_addr(key)
        idx = self._g.add_node(self._next, 0)[0]
        self._next += 1
        self._id_to_key[idx] = key
        self._key_to_id[key] = idx
        self._keys_by_addr[addr].add(key)
        return idx

    def key_of(self, idx: int) -> K:
        return self._id_to_key[idx]

    def block_keys(self) -> list[K]:
        id_to_key = self._id_to_key
        return [id_to_key[i] for i in self._g.nodes()]

    def ids_at(self, addr: int | SootAddressDescriptor) -> list[int]:
        key_to_id = self._key_to_id
        return [key_to_id[k] for k in self._keys_by_addr.get(addr, ())]

    def keys_at(self, addr: int | SootAddressDescriptor) -> list[K]:
        return list(self._keys_by_addr.get(addr, ()))

    def first_key_at(self, addr: int | SootAddressDescriptor) -> K | None:
        return next(iter(self._keys_by_addr.get(addr, ())), None)

    def has_addr(self, addr: int | SootAddressDescriptor) -> bool:
        return addr in self._keys_by_addr

    def addrs(self) -> list[int | SootAddressDescriptor]:
        return list(self._keys_by_addr)

    def __getstate__(self) -> dict:
        return {
            "id_to_key": self._id_to_key,
            "keys_by_addr": dict(self._keys_by_addr),
            "next": self._next,
            "objs": self._objs,
        }

    def __setstate__(self, state: dict) -> None:
        self._g = None  # type:ignore[assignment]  # re-bound by SpillingCFG.__setstate__
        self._id_to_key = state["id_to_key"]
        self._key_to_id = {key: idx for idx, key in self._id_to_key.items()}
        self._keys_by_addr = defaultdict(set, state["keys_by_addr"])
        self._next = state["next"]
        self._objs = state.get("objs", {})


class CFGSegmentStore:
    """
    Backend for paged :class:`CfgGraph` segments on the RuntimeDb: one LMDB sub-database shared by every graph of
    the knowledge base, keys prefixed with a per-graph random id. The database is opened on first use, so that a
    store can be attached before the RuntimeDb is usable (e.g. while a project is being unpickled).
    """

    DB_NAME = "cfgsegments"

    def __init__(self, rtdb: RuntimeDb):
        self.rtdb = rtdb
        self._db: str | None = None
        self._prefix = uuid.uuid4().bytes

    def _open(self) -> str:
        if self._db is None:
            self._db = self.rtdb.open_db(self.DB_NAME, unique=False)
        return self._db

    def _key(self, window: int) -> bytes:
        return self._prefix + window.to_bytes(8, "big")

    def get(self, window: int) -> bytes | None:
        with self.rtdb.begin_txn(self._open()) as txn:
            return txn.get(self._key(window))

    def put(self, window: int, data: bytes) -> None:
        db = self._open()
        while True:
            try:
                with self.rtdb.begin_txn(db, write=True) as txn:
                    txn.put(self._key(window), data)
                return
            except lmdb.MapFullError:
                if not self.rtdb.increase_lmdb_map_size():
                    raise

    def delete(self, window: int) -> None:
        with self.rtdb.begin_txn(self._open(), write=True) as txn:
            txn.delete(self._key(window))

    def delete_all(self) -> None:
        if self._db is None:
            return
        with self.rtdb.begin_txn(self._db, write=True) as txn:
            cursor = txn.cursor()
            if cursor.set_range(self._prefix):
                while cursor.key().startswith(self._prefix) and cursor.delete():
                    pass

    def __del__(self):
        with contextlib.suppress(Exception):
            self.delete_all()


class _NodeMap:
    """Read-only mapping (block key -> CFGNode) over the nodes of a graph; what ``CFGModel._nodes`` exposes."""

    __slots__ = ("_graph",)

    def __init__(self, graph: SpillingCFG):
        self._graph = graph

    def __getitem__(self, key: K) -> CFGNode:
        return self._graph.get_node_by_key(key)

    def __contains__(self, key: K) -> bool:
        return self._graph._keys.id_of(key) is not None

    def __iter__(self) -> Iterator[K]:
        return iter(self._graph._keys.block_keys())

    def __len__(self) -> int:
        return self._graph.number_of_nodes()

    def get(self, key: K, default: CFGNode | None = None) -> CFGNode | None:
        idx = self._graph._keys.id_of(key)
        return default if idx is None else self._graph._node_of_id(idx)

    def keys(self) -> Iterator[K]:
        return iter(self)

    def values(self) -> Iterator[CFGNode]:
        return iter(self._graph)

    def items(self) -> Iterator[tuple[K, CFGNode]]:
        for node in self._graph:
            yield get_block_key(node), node


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
            if node_attrs:
                for node in self._graph:
                    yield node, node_attrs.get(get_block_key(node), {})
            else:
                for node in self._graph:
                    yield node, {}
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
        node = g._bulk_node_getter()
        for src_id, dst_id in g._graph.edges():
            yield node(src_id), node(dst_id)

    @overload
    def __call__(self, data: Literal[False] = False) -> Iterator[tuple[CFGNode, CFGNode]]: ...
    @overload
    def __call__(self, data: Literal[True]) -> Iterator[tuple[CFGNode, CFGNode, dict]]: ...

    def __call__(
        self, data: bool = False
    ) -> Iterator[tuple[CFGNode, CFGNode]] | Iterator[tuple[CFGNode, CFGNode, dict]]:
        if data:
            g = self._graph
            node = g._bulk_node_getter()
            for src_id, dst_id, edge_data in g._graph.edges_with_data():
                yield node(src_id), node(dst_id), g._merge_extra(src_id, dst_id, edge_data)
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
    A networkx-compatible directed graph of CFGNodes over the packed Rust store :class:`CfgGraph`, keyed by block
    keys. For integer-keyed graphs the node records live in the store too (and are paged with it); nodes handed out
    are CFGNode views, and the same node is returned for repeated lookups while it is alive or recently used.

    addr_type must be "int", "block_id", or "soot". You can change addr_type before the first node is inserted but not
    after, since it affects how keys are mapped onto the store.
    """

    _addr_type: CFG_ADDR_TYPES

    def __init__(
        self,
        rtdb: RuntimeDb | None = None,
        cfg_model: CFGModel | None = None,
        cache_limit: int | None = None,  # pylint:disable=unused-argument
        db_batch_size: int = 800,  # pylint:disable=unused-argument
        addr_type: CFG_ADDR_TYPES = "int",
        segment_budget: int | None = None,
    ):
        """
        :param cache_limit:     Unused; kept for compatibility (node records are paged with the graph segments).
        :param db_batch_size:   Unused; kept for compatibility.
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
        if self._graph.number_of_nodes() > 0:
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

    def _import_node_fields(self, cmsg_nodes) -> None:
        """Set the record fields of integer-keyed nodes from serialized CFGNode messages (nodes are created as
        needed)."""
        if not isinstance(self._keys, _IntKeys):
            raise TypeError("node fields can only be imported into an integer-keyed graph")
        model = self._cfg_model
        add_node_rec = self._graph.add_node_rec
        for pb in cmsg_nodes:
            if pb.block_id and pb.block_id[0] != pb.ea:
                raise ValueError(f"CFG node {pb.ea:#x} has a block ID other than its address")
            byte_string = pb.byte_string if pb.HasField("byte_string") else None
            mode, manual = bytes_mode_of(model, pb.ea, pb.size, pb.thumb, byte_string)
            add_node_rec(
                pb.ea,
                pb.size,
                pb.function_address if pb.HasField("function_address") else None,
                pb.ins_base_addr,
                pb.ins_sizes,
                pb.thumb,
                pb.is_syscall,
                pb.no_ret if pb.HasField("no_ret") else None,
                mode,
                manual,
                pb.name if pb.HasField("name") else None,
                pb.simprocedure_name if pb.HasField("simprocedure_name") else None,
            )

    @property
    def _cfg_model(self) -> CFGModel | None:
        if self._cfg_model_ref is None:
            return None
        return self._cfg_model_ref()

    @_cfg_model.setter
    def _cfg_model(self, value: CFGModel | None) -> None:
        self._cfg_model_ref = weakref.ref(value) if value is not None else None

    @property
    def _nodes(self) -> _NodeMap:
        """A mapping view (block key -> CFGNode) over the nodes."""
        return _NodeMap(self)

    def get_node_by_key(self, block_key: K) -> CFGNode:
        """Get a CFGNode by block key."""
        idx = self._keys.id_of(block_key)
        if idx is None:
            raise KeyError(block_key)
        return self._node_of_id(idx)

    @property
    def node_keys(self) -> Iterator[K]:
        """Get an iterator over all block_keys in the graph."""
        yield from self._keys.block_keys()

    #
    # id <-> key <-> node helpers
    #

    def _id_of_node(self, node: CFGNode) -> int | None:
        if node._store is self._graph:
            return node._id
        return self._keys.id_of(get_block_key(node))

    def _node_of_id(self, idx: int) -> CFGNode:
        return self._keys.node_of_id(idx, self._cfg_model)

    def _ids_of_nbunch(self, nbunch) -> list[int]:
        nodes = [nbunch] if isinstance(nbunch, CFGNode) else nbunch
        ids = []
        for node in nodes:
            idx = self._id_of_node(node)
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
        self._keys.add_node(node, self._cfg_model)
        if attr:
            self._node_attrs.setdefault(get_block_key(node), {}).update(attr)

    def remove_node(self, node: CFGNode) -> None:
        idx = self._id_of_node(node)
        if self._node_attrs:
            self._node_attrs.pop(get_block_key(node), None)
        if idx is not None:
            self._drop_extra_for_node(idx)
            self._keys.remove(idx)

    def has_node(self, node: CFGNode) -> bool:
        return self._id_of_node(node) is not None

    def nodes_by_addr(self, addr: int) -> Iterator[CFGNode]:
        node_of_id = self._node_of_id
        for idx in self._keys.ids_at(addr):
            yield node_of_id(idx)

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
        return self._keys.iter_nodes(self._cfg_model)

    def _bulk_node_getter(self):
        """A `id -> CFGNode` function for whole-graph traversals (node fields are fetched in one store call)."""
        keys = self._keys
        model = self._cfg_model
        prefetch = keys.prefetch()
        node_of_id = keys.node_of_id
        if prefetch is None:
            return lambda idx: node_of_id(idx, model)
        get = prefetch.get
        return lambda idx: node_of_id(idx, model, get(idx))

    #
    # Edge operations
    #

    def add_edge(self, src: CFGNode, dst: CFGNode, **attr) -> None:
        # the passed objects become the graph's nodes (this is how _shrink_node replaces nodes)
        add_node = self._keys.add_node
        model = self._cfg_model
        self._add_edge_ids(add_node(src, model), add_node(dst, model), attr)

    def add_edge_by_key(self, src_block_key: K, dst_block_key: K, **attr) -> None:
        keys = self._keys
        src_id = keys.id_of(src_block_key)
        if src_id is None:
            src_id = keys.add_key(src_block_key)
        dst_id = keys.id_of(dst_block_key)
        if dst_id is None:
            dst_id = keys.add_key(dst_block_key)
        self._add_edge_ids(src_id, dst_id, attr)

    def _add_edge_ids(self, src_id: int, dst_id: int, attr: dict) -> None:
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
        src_id = self._id_of_node(src)
        dst_id = self._id_of_node(dst)
        if src_id is None or dst_id is None or not self._graph.remove_edge(src_id, dst_id):
            raise networkx.NetworkXError(f"The edge {src}-{dst} is not in the graph.")
        if self._extra_edge_attrs:
            self._extra_edge_attrs.pop((src_id, dst_id), None)

    def remove_edge_by_key(self, src_block_key: K, dst_block_key: K) -> None:
        src_id = self._keys.id_of(src_block_key)
        dst_id = self._keys.id_of(dst_block_key)
        if src_id is None or dst_id is None or not self._graph.remove_edge(src_id, dst_id):
            raise networkx.NetworkXError(f"The edge {src_block_key}-{dst_block_key} is not in the graph.")
        if self._extra_edge_attrs:
            self._extra_edge_attrs.pop((src_id, dst_id), None)

    def has_edge(self, src: CFGNode, dst: CFGNode) -> bool:
        src_id = self._id_of_node(src)
        if src_id is None:
            return False
        dst_id = self._id_of_node(dst)
        return dst_id is not None and self._graph.has_edge(src_id, dst_id)

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

    def successors_and_jumpkinds(self, node: CFGNode) -> list[tuple[CFGNode, str | None]]:
        """`(successor, jumpkind)` of every out-edge, without building edge-data dicts."""
        idx = self._id_of_node(node)
        if idx is None:
            return []
        node_of_id = self._node_of_id
        return [(node_of_id(dst_id), jk) for dst_id, jk in self._graph.out_edges_jumpkinds(idx)]

    def predecessors_and_jumpkinds(self, node: CFGNode) -> list[tuple[CFGNode, str | None]]:
        """`(predecessor, jumpkind)` of every in-edge, without building edge-data dicts."""
        idx = self._id_of_node(node)
        if idx is None:
            return []
        node_of_id = self._node_of_id
        return [(node_of_id(src_id), jk) for src_id, jk in self._graph.in_edges_jumpkinds(idx)]

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
            addr_type=self._addr_type,
            segment_budget=self._segment_budget,
        )

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
        self._keys.clear()  # detaches live views before their records go away
        self._graph.clear()
        self._extra_edge_attrs.clear()
        self._node_attrs.clear()

        for node in nx_graph.nodes():
            self.add_node(node)

        for src, dst, data in nx_graph.edges(data=True):
            self.add_edge(src, dst, **data)

    def set_rtdb(self, rtdb: RuntimeDb | None) -> None:
        """
        (Re-)attach a RuntimeDb to this graph. This is used after unpickling (rtdb references are not preserved
        across pickling) so that segment paging works again.
        """
        self._rtdb = rtdb
        if rtdb is not None:
            self._init_paging()

    #
    # Pickling
    #

    def __getstate__(self):
        return {
            "graph": self._graph,
            "keys": self._keys if isinstance(self._keys, _ObjKeys) else None,
            "extra_edge_attrs": self._extra_edge_attrs,
            "node_attrs": self._node_attrs,
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
        self._segment_budget = state["segment_budget"]
        self._cfg_model_ref = None
        self._rtdb = None

        legacy_nodes = state.get("nodes")
        if legacy_nodes is not None:
            # a pickle from before node records lived in the store: nodes come as plain objects
            self._load_legacy_nodes(legacy_nodes["items"])

    def _load_legacy_nodes(self, items: dict[K, CFGNode]) -> None:
        keys = self._keys
        if isinstance(keys, _IntKeys):
            for node in items.values():
                node._cfg_model = None
                keys.add_node(node, None)
            # views are created afresh, with the model the graph gets once CFGModel.__setstate__ runs
            keys.detach_all()
        else:
            for key, node in items.items():
                idx = keys.id_of(key)
                if idx is not None:
                    keys._objs[idx] = node
