"""
LRU + LMDB spilling for the functions callgraph (a ``networkx.MultiDiGraph`` of function-address edges).

``SpillingMultiDiGraph`` subclasses ``networkx.MultiDiGraph`` and only replaces the outer adjacency-dict
factory (used for both ``_adj``/``_succ`` and ``_pred``) with a spilling dict. Because networkx's own
algorithms and the ``networkx.MultiDiGraph(callgraph)`` / ``networkx.DiGraph(callgraph)`` conversions
operate through ``_adj``/``_pred``/``_node`` -- which remain fully dict-compatible -- they keep working
unchanged. Only the per-node adjacency (the bulk of a large callgraph's memory) is spilled to disk; the
node dict stays resident.

Callgraph edge attribute dicts are tiny (a single ``{"type": <str>}``) and immutable once created, so the
outer adjacency entries are serialized whole with :mod:`pickle` on eviction (always, since the nested
adjacency structure is mutated in place by networkx). Insertion order is preserved to match a plain
networkx adjacency dict, so downstream order-sensitive algorithms behave identically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import networkx

from angr.knowledge_plugins.spilling_dict import SpillingObjectDict

if TYPE_CHECKING:
    from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb


class SpillingCallgraphAdjDict(SpillingObjectDict[int, dict]):
    """
    Outer adjacency dict for :class:`SpillingMultiDiGraph`: maps a node (function address) to its inner
    adjacency dict ``{neighbor: {edge_key: {"type": str}}}``, with LRU caching and LMDB spilling.
    """

    _DB_NAME = "callgraph"
    _SORTED = False  # preserve networkx insertion order


class SpillingMultiDiGraph(networkx.MultiDiGraph):
    """
    A ``networkx.MultiDiGraph`` whose outer adjacency dicts (``_adj``/``_succ`` and ``_pred``) spill to the
    RuntimeDb via an LRU cache. Drop-in compatible with a plain ``MultiDiGraph``.

    :param rtdb:            RuntimeDb used for LMDB access (``None`` disables spilling).
    :param cache_limit:     Maximum number of node adjacency entries to keep resident per outer dict, or
                            ``None`` to never spill.
    :param db_batch_size:   Number of adjacency entries evicted in a single batch.
    """

    # class-level default so adjlist_outer_dict_factory() works during networkx's __init__
    _rtdb: RuntimeDb | None = None
    _cg_cache_limit: int | None = None
    _cg_db_batch_size: int = 400

    def __init__(
        self,
        rtdb: RuntimeDb | None = None,
        cache_limit: int | None = None,
        db_batch_size: int = 400,
        incoming_graph_data=None,
        **attr,
    ):
        self._rtdb = rtdb
        self._cg_cache_limit = cache_limit
        self._cg_db_batch_size = db_batch_size
        super().__init__(incoming_graph_data, **attr)

    def adjlist_outer_dict_factory(self) -> SpillingCallgraphAdjDict:  # type: ignore[override]
        return SpillingCallgraphAdjDict(
            self._rtdb, cache_limit=self._cg_cache_limit, db_batch_size=self._cg_db_batch_size
        )

    #
    # Edge insertion
    #
    # networkx relies on _adj[u][v] and _pred[v][u] being the *same* keydict object: when a parallel edge is
    # added to an already-existing (u, v) pair it mutates only _adj[u][v] in place. Spilling stores _adj and
    # _pred independently, so a reload breaks that shared identity and _pred goes stale. We re-point _pred[v][u]
    # at the (authoritative) _adj[u][v] keydict after every insertion to keep the two indexes consistent.
    #

    def add_edge(self, u_for_edge, v_for_edge, key=None, **attr):  # type: ignore[override]
        k = super().add_edge(u_for_edge, v_for_edge, key=key, **attr)
        self._pred[v_for_edge][u_for_edge] = self._adj[u_for_edge][v_for_edge]
        return k

    def add_edges_from(self, ebunch_to_add, **attr):  # type: ignore[override]
        keys = []
        for e in ebunch_to_add:
            ne = len(e)
            if ne == 4:
                u, v, key, dd = e
            elif ne == 3:
                u, v, dd = e
                key = None
            elif ne == 2:
                u, v = e
                key = None
                dd = {}
            else:
                raise networkx.NetworkXError(f"Edge tuple {e} must be a 2-, 3-, or 4-tuple.")
            keys.append(self.add_edge(u, v, key, **{**attr, **dd}))
        return keys

    #
    # Spilling helpers
    #

    def load_all_spilled(self) -> None:
        if isinstance(self._adj, SpillingCallgraphAdjDict):
            self._adj.load_all_spilled()
        if isinstance(self._pred, SpillingCallgraphAdjDict):
            self._pred.load_all_spilled()

    def set_rtdb(self, rtdb: RuntimeDb | None) -> None:
        """(Re-)attach a RuntimeDb to this graph and its adjacency containers (e.g. after unpickling)."""
        self._rtdb = rtdb
        if isinstance(self._adj, SpillingCallgraphAdjDict):
            self._adj.set_rtdb(rtdb)
        if isinstance(self._pred, SpillingCallgraphAdjDict):
            self._pred.set_rtdb(rtdb)

    #
    # Pickling: materialize adjacency, then rebuild a fresh graph (rtdb is not preserved across pickling).
    #

    @staticmethod
    def _rebuild(cache_limit, db_batch_size, node_dict, adj_items, graph_attr):
        g = SpillingMultiDiGraph(rtdb=None, cache_limit=cache_limit, db_batch_size=db_batch_size)
        g.graph.update(graph_attr)
        for n, ndata in node_dict.items():
            g.add_node(n, **ndata)
        for u, nbrs in adj_items:
            for v, keydict in nbrs.items():
                for key, data in keydict.items():
                    g.add_edge(u, v, key=key, **data)
        return g

    def __reduce__(self):
        self.load_all_spilled()
        adj_items = [(u, {v: dict(kd) for v, kd in nbrs.items()}) for u, nbrs in self._adj.items()]
        node_dict = {n: dict(d) for n, d in self._node.items()}
        return (
            self._rebuild,
            (self._cg_cache_limit, self._cg_db_batch_size, node_dict, adj_items, dict(self.graph)),
        )
