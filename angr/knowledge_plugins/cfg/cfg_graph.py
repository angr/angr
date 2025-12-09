# pylint:disable=too-many-public-methods
from __future__ import annotations

import rustworkx as rx


class _RxNodeView:
    """Networkx-compatible node view for RxDiGraph."""

    __slots__ = ("_graph",)

    def __init__(self, graph):
        self._graph = graph

    def __call__(self, data=False):
        if data:
            return [(node, {}) for node in self._graph._node_to_idx.keys()]
        return self

    def __contains__(self, n):
        return n in self._graph._node_to_idx

    def __eq__(self, other):
        if isinstance(other, _RxNodeView):
            return set(self) == set(other)
        try:
            return set(self) == set(other)
        except TypeError:
            return NotImplemented

    def __iter__(self):
        return iter(self._graph._node_to_idx.keys())

    def __len__(self):
        return self._graph.number_of_nodes()


class _RxEdgeView:
    """Networkx-compatible edge view for RxDiGraph."""

    __slots__ = ("_graph",)

    def __init__(self, graph):
        self._graph = graph

    def __call__(self, data=False):
        if data:
            return self._graph.get_edges(data=True)
        return self

    def __eq__(self, other):
        if isinstance(other, _RxEdgeView):
            return set(self) == set(other)
        try:
            return set(self) == set(other)
        except TypeError:
            return NotImplemented

    def __iter__(self):
        return self._graph._iter_edges()

    def __len__(self):
        return self._graph.number_of_edges()


class _RxOutDegreeView:
    """Networkx-compatible out_degree view for RxDiGraph."""

    __slots__ = ("_graph",)

    def __init__(self, graph):
        self._graph = graph

    def __call__(self, nbunch=None):
        if nbunch is not None and nbunch in self._graph._node_to_idx:
            return self[nbunch]
        if nbunch is None:
            return iter(self)

        def _iter():
            for node in nbunch:
                idx = self._graph._node_to_idx.get(node)
                if idx is not None:
                    yield (node, self._graph._g.out_degree(idx))

        return _iter()

    def __getitem__(self, node):
        idx = self._graph._node_to_idx.get(node)
        if idx is None:
            raise KeyError(f"Node {node} not in graph")
        return self._graph._g.out_degree(idx)

    def __iter__(self):
        for node, idx in self._graph._node_to_idx.items():
            yield (node, self._graph._g.out_degree(idx))

    def __len__(self):
        return len(self._graph._node_to_idx)


class _RxInDegreeView:
    """Networkx-compatible in_degree view for RxDiGraph."""

    __slots__ = ("_graph",)

    def __init__(self, graph):
        self._graph = graph

    def __call__(self, nbunch=None):
        if nbunch is not None and nbunch in self._graph._node_to_idx:
            return self[nbunch]
        if nbunch is None:
            return iter(self)

        def _iter():
            for node in nbunch:
                idx = self._graph._node_to_idx.get(node)
                if idx is not None:
                    yield (node, self._graph._g.in_degree(idx))

        return _iter()

    def __getitem__(self, node):
        idx = self._graph._node_to_idx.get(node)
        if idx is None:
            raise KeyError(f"Node {node} not in graph")
        return self._graph._g.in_degree(idx)

    def __iter__(self):
        for node, idx in self._graph._node_to_idx.items():
            yield (node, self._graph._g.in_degree(idx))

    def __len__(self):
        return len(self._graph._node_to_idx)


class _RxAdjacencyView:
    """Networkx-compatible adjacency view for RxDiGraph.__getitem__."""

    __slots__ = ("_graph", "_node_idx")

    def __init__(self, graph, node_idx):
        self._graph = graph
        self._node_idx = node_idx

    def __iter__(self):
        yield from self._graph._g.successors(self._node_idx)

    def __len__(self):
        return self._graph._g.out_degree(self._node_idx)

    def __contains__(self, node):
        if node not in self._graph._node_to_idx:
            return False
        succ_idx = self._graph._node_to_idx[node]
        return self._graph._g.has_edge(self._node_idx, succ_idx)

    def __getitem__(self, node):
        if node not in self._graph._node_to_idx:
            raise KeyError(f"Node {node} not in graph")
        succ_idx = self._graph._node_to_idx[node]
        if not self._graph._g.has_edge(self._node_idx, succ_idx):
            raise KeyError(f"No edge from node to {node}")
        try:
            data = self._graph._g.get_edge_data(self._node_idx, succ_idx)
            return data if data is not None else {}
        except Exception:
            return {}

    def keys(self):
        return list(self)

    def values(self):
        return [self[succ] for succ in self]

    def items(self):
        return [(succ, self[succ]) for succ in self]


class RxDiGraph:
    """
    A networkx.DiGraph-compatible wrapper around rustworkx.PyDiGraph.

    This class provides a compatibility layer that allows rustworkx to be used
    for better performance while maintaining the networkx API patterns used
    throughout the angr codebase.
    """

    __slots__ = (
        "_g",
        "_idx_to_node",
        "_node_to_idx",
    )

    def __init__(self):
        self._g = rx.PyDiGraph(multigraph=False)
        self._node_to_idx: dict = {}
        self._idx_to_node: dict = {}

    @property
    def nodes(self):
        return _RxNodeView(self)

    @property
    def edges(self):
        return _RxEdgeView(self)

    @property
    def in_degree(self):
        return _RxInDegreeView(self)

    @property
    def out_degree(self):
        return _RxOutDegreeView(self)

    @property
    def succ(self):
        return self

    def __contains__(self, node):
        return node in self._node_to_idx

    def __iter__(self):
        return iter(self._node_to_idx.keys())

    def __len__(self):
        return self.number_of_nodes()

    def __getattr__(self, name):
        return getattr(self._g, name)

    def __getitem__(self, node):
        if node not in self._node_to_idx:
            raise KeyError(f"Node {node} not in graph")
        return _RxAdjacencyView(self, self._node_to_idx[node])

    def add_node(self, node):
        if node not in self._node_to_idx:
            idx = self._g.add_node(node)
            self._node_to_idx[node] = idx
            self._idx_to_node[idx] = node
            return idx
        return self._node_to_idx[node]

    def add_nodes_from(self, nodes):
        for node in nodes:
            self.add_node(node)

    def has_node(self, node):
        return node in self._node_to_idx

    def remove_node(self, node):
        idx = self._node_to_idx.pop(node, None)
        if idx is not None:
            self._idx_to_node.pop(idx, None)
            try:
                self._g.remove_node(idx)
            except Exception:
                pass

    def remove_nodes_from(self, nodes):
        indices = []
        for node in nodes:
            idx = self._node_to_idx.pop(node, None)
            if idx is not None:
                self._idx_to_node.pop(idx, None)
                indices.append(idx)
        self._g.remove_nodes_from(indices)

    def predecessors(self, node):
        idx = self._node_to_idx.get(node)
        if idx is None:
            return []
        return self._g.predecessors(idx)

    def successors(self, node):
        idx = self._node_to_idx.get(node)
        if idx is None:
            return []
        return self._g.successors(idx)

    def add_edge(self, src, dst, **data):
        src_idx = self._get_node_idx(src)
        dst_idx = self._get_node_idx(dst)
        self._g.add_edge(src_idx, dst_idx, data if data else None)

    def has_edge(self, src, dst):
        if src not in self._node_to_idx or dst not in self._node_to_idx:
            return False
        src_idx = self._node_to_idx[src]
        dst_idx = self._node_to_idx[dst]
        return self._g.has_edge(src_idx, dst_idx)

    def remove_edge(self, src, dst):
        if src not in self._node_to_idx or dst not in self._node_to_idx:
            return
        src_idx = self._node_to_idx[src]
        dst_idx = self._node_to_idx[dst]
        try:
            self._g.remove_edge(src_idx, dst_idx)
        except Exception:
            pass

    def get_edge_data(self, u, v, default=None):
        if u not in self._node_to_idx or v not in self._node_to_idx:
            return default
        u_idx = self._node_to_idx[u]
        v_idx = self._node_to_idx[v]
        try:
            data = self._g.get_edge_data(u_idx, v_idx)
            return data if data is not None else {}
        except (rx.NoEdgeBetweenNodes, IndexError):
            return default

    def get_edges(self, data=False):
        edges_list = []
        if not data:
            for src_idx, dst_idx in self._g.edge_list():
                src_node = self._idx_to_node.get(src_idx)
                dst_node = self._idx_to_node.get(dst_idx)
                if src_node is not None and dst_node is not None:
                    edges_list.append((src_node, dst_node))
        else:
            for src_idx, dst_idx, edge_payload in self._g.weighted_edge_list():
                src_node = self._idx_to_node.get(src_idx)
                dst_node = self._idx_to_node.get(dst_idx)
                if src_node is not None and dst_node is not None:
                    edge_data = edge_payload if edge_payload is not None else {}
                    edges_list.append((src_node, dst_node, edge_data))
        return edges_list

    def in_edges(self, nodes=None, data=False):
        if nodes is None:
            nodes = list(self.nodes)
        elif not isinstance(nodes, (list, tuple, set)):
            nodes = [nodes]

        edges = []
        for node in nodes:
            if node not in self._node_to_idx:
                continue
            dst_idx = self._node_to_idx[node]
            for src_idx, _, edge_data in self._g.in_edges(dst_idx):
                src_node = self._idx_to_node.get(src_idx)
                if src_node is None:
                    continue
                if data:
                    edges.append((src_node, node, edge_data if edge_data is not None else {}))
                else:
                    edges.append((src_node, node))
        return edges

    def out_edges(self, nodes=None, data=False):
        if nodes is None:
            nodes = list(self.nodes)
        elif not isinstance(nodes, (list, tuple, set)):
            nodes = [nodes]

        edges = []
        for node in nodes:
            if node not in self._node_to_idx:
                continue
            src_idx = self._node_to_idx[node]
            for _, dst_idx, edge_data in self._g.out_edges(src_idx):
                dst_node = self._idx_to_node.get(dst_idx)
                if dst_node is None:
                    continue
                if data:
                    edges.append((node, dst_node, edge_data if edge_data is not None else {}))
                else:
                    edges.append((node, dst_node))
        return edges

    def number_of_nodes(self):
        return len(self._node_to_idx)

    def number_of_edges(self):
        return self._g.num_edges()

    def copy(self):
        new_g = RxDiGraph()
        new_g._g = self._g.copy()
        new_g._node_to_idx = self._node_to_idx.copy()
        new_g._idx_to_node = self._idx_to_node.copy()
        return new_g

    def subgraph(self, nodes):
        indices = []
        for node in nodes:
            if node in self._node_to_idx:
                indices.append(self._node_to_idx[node])

        rx_subgraph = self._g.subgraph(indices)

        new_g = RxDiGraph()
        new_g._g = rx_subgraph

        for new_idx in rx_subgraph.node_indices():
            node = rx_subgraph[new_idx]
            new_g._node_to_idx[node] = new_idx
            new_g._idx_to_node[new_idx] = node

        return new_g

    def simple_cycles(self):
        for cycle_indices in rx.simple_cycles(self._g):
            yield [self._idx_to_node[idx] for idx in cycle_indices if idx in self._idx_to_node]

    def _iter_edges(self):
        for src_idx, dst_idx in self._g.edge_list():
            src_node = self._idx_to_node.get(src_idx)
            dst_node = self._idx_to_node.get(dst_idx)
            if src_node is not None and dst_node is not None:
                yield (src_node, dst_node)

    def _get_node_idx(self, node):
        idx = self._node_to_idx.get(node)
        if idx is None:
            idx = self._g.add_node(node)
            self._node_to_idx[node] = idx
            self._idx_to_node[idx] = node
        return idx
