from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import networkx

READ_ONLY_MESSAGE = "read-only view of Function.transition_graph; mutate through the Function API"


class ReadOnlyGraphError(networkx.NetworkXError):
    """
    Raised by every mutating operation on a Function graph view.
    """


def _read_only(*_args, **_kwargs):
    raise ReadOnlyGraphError(READ_ONLY_MESSAGE)


class ReadOnlyAttrDict(dict):
    """
    The attribute dictionary of a node, an edge or the graph of a Function graph view. Reads like a dict; every write
    raises ReadOnlyGraphError. Copies (``copy()``, ``dict(d)``, pickling, ``copy.deepcopy``) are plain dicts.
    """

    __slots__ = ()

    __setitem__ = _read_only
    __delitem__ = _read_only
    __ior__ = _read_only
    clear = _read_only
    pop = _read_only
    popitem = _read_only
    setdefault = _read_only
    update = _read_only

    def copy(self) -> dict:
        return dict(self)

    def __reduce__(self):
        return dict, (dict(self),)


def _write(d: ReadOnlyAttrDict, key: str, value: Any) -> None:
    dict.__setitem__(d, key, value)


def _plain_digraph(graph_attrs: dict, nodes: list, edges: list) -> networkx.DiGraph:
    g = networkx.DiGraph()
    g.graph.update(graph_attrs)
    g.add_nodes_from(nodes)
    g.add_edges_from(edges)
    return g


class TransitionGraph(networkx.DiGraph):
    """
    A read-only networkx DiGraph over the nodes and edges of a Function's transition graph (``transition_graph``) or
    its local part (``graph``). The owning Function keeps it in sync with its store; nothing else can write it:
    every mutating method raises ReadOnlyGraphError, attribute dictionaries are ReadOnlyAttrDicts, and
    ``networkx.is_frozen()`` is True. ``copy()``, ``reverse()``, ``to_directed()``, ``to_undirected()``,
    ``subgraph(...).copy()``, ``networkx.DiGraph(view)``, pickling and deep-copying all produce ordinary mutable
    networkx graphs that are detached from the Function.
    """

    frozen = True
    node_attr_dict_factory = ReadOnlyAttrDict
    edge_attr_dict_factory = ReadOnlyAttrDict

    def __init__(self, incoming_graph_data=None, **attr):
        if incoming_graph_data is not None:
            raise TypeError("TransitionGraph views are built by Function; use networkx.DiGraph(view) for a copy")
        super().__init__(None, **attr)
        self.graph = ReadOnlyAttrDict(self.graph)

    # networkx detaches copies through self.__class__() followed by add_*; produce plain graphs instead

    def copy(self, as_view: bool = False):
        if as_view:
            return networkx.graphviews.generic_graph_view(self)
        return _plain_digraph(dict(self.graph), list(self.nodes(data=True)), list(self.edges(data=True)))

    def to_directed(self, as_view: bool = False):
        if as_view:
            return networkx.graphviews.generic_graph_view(self, networkx.DiGraph)
        return self.copy()

    def to_undirected(self, reciprocal: bool = False, as_view: bool = False):
        if as_view:
            return networkx.graphviews.generic_graph_view(self, networkx.Graph)
        g = networkx.Graph()
        g.graph.update(self.graph)
        g.add_nodes_from(self.nodes(data=True))
        g.add_edges_from((u, v, d) for u, v, d in self.edges(data=True) if not reciprocal or self.has_edge(v, u))  # pylint:disable=arguments-out-of-order
        return g

    def reverse(self, copy: bool = True):
        if not copy:
            return networkx.reverse_view(self)
        return _plain_digraph(
            dict(self.graph), list(self.nodes(data=True)), [(v, u, d) for u, v, d in self.edges(data=True)]
        )

    def __reduce__(self):
        return _plain_digraph, (dict(self.graph), list(self.nodes(data=True)), list(self.edges(data=True)))

    # mutators

    add_node = _read_only
    add_nodes_from = _read_only
    add_edge = _read_only
    add_edges_from = _read_only
    add_weighted_edges_from = _read_only
    remove_node = _read_only
    remove_nodes_from = _read_only
    remove_edge = _read_only
    remove_edges_from = _read_only
    clear = _read_only
    clear_edges = _read_only
    update = _read_only

    #
    # mirror maintenance, for the owning Function only
    #

    def _mirror_add_node(self, node) -> None:
        if node not in self._node:
            self._succ[node] = self.adjlist_inner_dict_factory()
            self._pred[node] = self.adjlist_inner_dict_factory()
            self._node[node] = ReadOnlyAttrDict()
            networkx._clear_cache(self)

    def _mirror_add_nodes(self, nodes: Iterable) -> None:
        for node in nodes:
            self._mirror_add_node(node)

    def _mirror_add_edge(self, src, dst, data: dict[str, Any]) -> None:
        self._mirror_add_node(src)
        self._mirror_add_node(dst)
        existing = self._succ[src].get(dst)
        merged = ReadOnlyAttrDict(existing) if existing is not None else ReadOnlyAttrDict()
        for key, value in data.items():
            _write(merged, key, value)
        self._succ[src][dst] = merged
        self._pred[dst][src] = merged
        networkx._clear_cache(self)

    def _mirror_add_edges(self, edges: Iterable[tuple[Any, Any, dict[str, Any]]]) -> None:
        for src, dst, data in edges:
            self._mirror_add_edge(src, dst, data)

    def _mirror_set_edge_attr(self, src, dst, key: str, value: Any) -> None:
        _write(self._succ[src][dst], key, value)

    def _mirror_remove_edge(self, src, dst) -> None:
        if dst in self._succ.get(src, ()):
            del self._succ[src][dst]
            del self._pred[dst][src]
            networkx._clear_cache(self)

    def _mirror_remove_node(self, node) -> None:
        if node in self._node:
            for dst in list(self._succ[node]):
                del self._pred[dst][node]
            for src in list(self._pred[node]):
                del self._succ[src][node]
            del self._succ[node]
            del self._pred[node]
            del self._node[node]
            networkx._clear_cache(self)
