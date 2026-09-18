from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

import networkx

if TYPE_CHECKING:
    from angr.codenode import CodeNode

    from .function import Function


class TransitionGraph(networkx.DiGraph):
    """
    The networkx view of a Function's transition graph. It mirrors the Rust-backed FunctionGraph store and writes
    every in-place mutation (add_node, add_edge, remove_*) through to it, so code that mutates
    ``func.transition_graph`` directly keeps working. Instances created by networkx itself (``copy()``,
    ``subgraph()``, ``reverse()``) have no owning function and behave like plain DiGraphs.
    """

    def __init__(self, incoming_graph_data=None, function: Function | None = None, **attr):
        super().__init__(incoming_graph_data, **attr)
        self._function = function

    #
    # mirror maintenance: the owning Function calls these to keep the view in sync without triggering write-through
    #

    def _mirror_add_node(self, node: CodeNode) -> None:
        networkx.DiGraph.add_node(self, node)

    def _mirror_add_nodes(self, nodes: Iterable[CodeNode]) -> None:
        networkx.DiGraph.add_nodes_from(self, nodes)

    def _mirror_add_edges(self, edges: Iterable[tuple[CodeNode, CodeNode, dict[str, Any]]]) -> None:
        networkx.DiGraph.add_edges_from(self, edges)

    def _mirror_add_edge(self, src: CodeNode, dst: CodeNode, data: dict[str, Any]) -> None:
        networkx.DiGraph.add_edge(self, src, dst, **data)

    def _mirror_remove_edge(self, src: CodeNode, dst: CodeNode) -> None:
        if self.has_edge(src, dst):
            networkx.DiGraph.remove_edge(self, src, dst)

    def _mirror_remove_node(self, node: CodeNode) -> None:
        if node in self:
            networkx.DiGraph.remove_node(self, node)

    #
    # write-through mutators
    #

    def add_node(self, node_for_adding, **attr):
        if self._function is not None:
            self._function._store_add_node(node_for_adding)
        super().add_node(node_for_adding, **attr)

    def add_nodes_from(self, nodes_for_adding, **attr):
        for n in nodes_for_adding:
            if isinstance(n, tuple) and len(n) == 2 and isinstance(n[1], dict):
                self.add_node(n[0], **{**attr, **n[1]})
            else:
                self.add_node(n, **attr)

    def add_edge(self, u_of_edge, v_of_edge, **attr):
        if self._function is not None:
            self._function._store_add_edge(u_of_edge, v_of_edge, attr)
        super().add_edge(u_of_edge, v_of_edge, **attr)

    def add_edges_from(self, ebunch_to_add, **attr):
        for e in ebunch_to_add:
            if len(e) == 3:
                u, v, dd = e
                self.add_edge(u, v, **{**attr, **dd})
            else:
                u, v = e
                self.add_edge(u, v, **attr)

    def remove_node(self, n):
        super().remove_node(n)
        if self._function is not None:
            self._function._store_remove_node(n)

    def remove_nodes_from(self, nodes):
        for n in list(nodes):
            if n in self:
                self.remove_node(n)

    def remove_edge(self, u, v):
        super().remove_edge(u, v)
        if self._function is not None:
            self._function._store_remove_edge(u, v)

    def remove_edges_from(self, ebunch):
        for e in ebunch:
            u, v = e[:2]
            if self.has_edge(u, v):
                self.remove_edge(u, v)

    def clear(self):
        if self._function is not None:
            for n in list(self.nodes):
                self._function._store_remove_node(n)
        super().clear()

    def clear_edges(self):
        if self._function is not None:
            for u, v in list(self.edges):
                self._function._store_remove_edge(u, v)
        super().clear_edges()
