from __future__ import annotations
import logging
from typing import Any
from collections import defaultdict

import networkx

from .structuring.structurer_nodes import MultiNode


l = logging.getLogger(name=__name__)


class GraphRegion:
    """
    GraphRegion represents a region of nodes.

    :ivar head:             The head of the region.
    :ivar graph:            The region graph.
    :ivar successors:       A set of successors of nodes in the graph. These successors do not belong to the current
                            region.
    :ivar graph_with_successors:    The region graph that includes successor nodes.
    """

    __slots__ = (
        "head",
        "graph",
        "successors",
        "graph_with_successors",
        "cyclic",
        "full_graph",
        "cyclic_ancestor",
        "_node_to_replaced_regions",
        "_replaced_regions",
    )

    def __init__(
        self,
        head,
        graph,
        successors: set | None,
        graph_with_successors: networkx.DiGraph | None,
        cyclic,
        full_graph: networkx.DiGraph | None,
        cyclic_ancestor: bool = False,
    ):
        self.head = head
        self.graph = graph
        self.successors = set(successors) if successors is not None else None
        # successors inside graph_with_successors should be treated as read-only. when deep-copying GraphRegion objects,
        # successors inside graph_with_successors are *not* deep copied. therefore, you should never modify any
        # successor node in graph_with_successors. to avoid potential programming errors, just treat
        # graph_with_successors as read-only.
        self.graph_with_successors = graph_with_successors

        self.full_graph = full_graph
        self.cyclic = cyclic
        self.cyclic_ancestor = cyclic_ancestor

        # store all subregions and their replacements
        self._node_to_replaced_regions = {}
        self._replaced_regions = {}

    def __repr__(self):
        addrs: list[int] = []
        s = ""
        if self.graph is None:
            # only head is available
            return f"<GraphRegion {self.head!r}>"

        for node in self.graph.nodes():
            if hasattr(node, "addr"):
                addrs.append(node.addr)
        if addrs:
            s = f": {min(addrs):#x}-{max(addrs):#x}"

        return "<GraphRegion %r of %d nodes%s>" % (self.head, self.graph.number_of_nodes(), s)

    def copy(self) -> GraphRegion:
        return GraphRegion(
            self.head,
            networkx.DiGraph(self.graph) if self.graph is not None else None,
            set(self.successors) if self.successors is not None else None,
            networkx.DiGraph(self.graph_with_successors) if self.graph_with_successors is not None else None,
            self.cyclic,
            networkx.DiGraph(self.full_graph) if self.full_graph is not None else None,
            cyclic_ancestor=self.cyclic_ancestor,
        )

    def recursive_copy(self, nodes_map=None):
        if nodes_map is None:
            nodes_map = {}
        new_graph = self._recursive_copy(self.graph, nodes_map)

        if self.graph_with_successors is not None:
            successors = set()
            for succ in self.successors:
                if succ not in nodes_map:
                    if isinstance(succ, GraphRegion):
                        nodes_map[succ] = succ.recursive_copy(nodes_map=nodes_map)
                    else:
                        nodes_map[succ] = succ
                successors.add(nodes_map[succ])

            new_graph_with_successors = self._recursive_copy(self.graph_with_successors, nodes_map)
        else:
            new_graph_with_successors = None
            successors = None

        new_full_graph = self._recursive_copy(self.full_graph, nodes_map) if self.full_graph is not None else None

        return GraphRegion(
            nodes_map[self.head],
            new_graph,
            successors,
            new_graph_with_successors,
            self.cyclic,
            new_full_graph,
            cyclic_ancestor=self.cyclic_ancestor,
        )

    @staticmethod
    def _recursive_copy(old_graph, nodes_map, ignored_nodes=None) -> networkx.DiGraph:
        new_graph = networkx.DiGraph()

        # make copy of each node and add the mapping from old nodes to new nodes into nodes_map
        for node in old_graph.nodes():
            if node in nodes_map:
                new_graph.add_node(nodes_map[node])
            elif ignored_nodes is not None and node in ignored_nodes:
                # do not copy. use the reference instead
                new_graph.add_node(node)
                # drop it into the nodes_map
                nodes_map[node] = node
            else:
                # make recursive copies
                if type(node) is GraphRegion:
                    new_node = node.recursive_copy(nodes_map=nodes_map)
                    nodes_map[node] = new_node
                elif type(node) is MultiNode:
                    new_node = node.copy()
                    nodes_map[node] = new_node
                else:
                    new_node = node
                    nodes_map[node] = new_node
                new_graph.add_node(new_node)

        # add all edges
        for src, dst, edge_data in old_graph.edges(data=True):
            new_graph.add_edge(nodes_map[src], nodes_map[dst], **edge_data)

        return new_graph

    @property
    def addr(self):
        return self.head.addr

    @staticmethod
    def dbg_get_repr(obj, ident=0):
        return obj.dbg_print(ident=ident) if type(obj) is GraphRegion else " " * ident + str(obj)

    def dbg_print(self, ident=0):
        s = self.dbg_get_repr(self.head, ident=ident) + "\n"

        successors = list(self.graph.successors(self.head))
        if len(successors) == 2:
            left_kid, right_kid = successors
            s += (
                " " * ident
                + "if (...) {\n"
                + self.dbg_get_repr(left_kid, ident=ident + 2)
                + "\n"
                + " " * ident
                + "}\n"
                + " " * ident
                + "else if (...) {\n"
                + self.dbg_get_repr(right_kid, ident=ident + 2)
                + "\n"
                + " " * ident
                + "}"
            )
            # TODO: other nodes
        elif len(successors) == 1:
            s += self.dbg_get_repr(successors[0], ident=ident)

        return s

    def replace_region(
        self,
        sub_region: GraphRegion,
        updated_sub_region: GraphRegion,
        replace_with,
        virtualized_edges: set[tuple[Any, Any]],
    ):
        if sub_region not in self.graph:
            l.error("The sub-region to replace must be in the current region. Note that this method is not recursive.")
            raise Exception

        if sub_region is self.head:
            self.head = replace_with

        # analyze sub_region and removed_edges to understand which edges in the current region to drop
        removed_edges_count_by_outside_preds = defaultdict(int)
        removed_edges_count_by_outside_succs = defaultdict(int)
        for src, dst in virtualized_edges:
            if src not in sub_region.graph and dst in sub_region.graph:
                # incoming edge
                removed_edges_count_by_outside_preds[src] += 1
            elif src in sub_region.graph and dst not in sub_region.graph:
                # outgoing edge
                removed_edges_count_by_outside_succs[dst] += 1

        edges_to_remove = set()
        for outside_pred, removed_edges_count in removed_edges_count_by_outside_preds.items():
            if (
                outside_pred in sub_region.graph_with_successors
                and sub_region.graph_with_successors.out_degree[outside_pred] == removed_edges_count
            ):
                # all incoming edges from this node are gone. this edge must go away
                edges_to_remove.add((outside_pred, sub_region))
        for outside_succ, removed_edges_count in removed_edges_count_by_outside_succs.items():
            if (
                outside_succ in sub_region.graph_with_successors
                and sub_region.graph_with_successors.in_degree[outside_succ] == removed_edges_count
            ):
                # all outgoing edges to this node are gone. this edge must go away
                edges_to_remove.add((sub_region, outside_succ))

        self._replace_node_in_graph(self.graph, sub_region, replace_with, edges_to_remove)
        if self.graph_with_successors is not None:
            if sub_region.successors != updated_sub_region.successors:
                # some successors are no longer in use - remove them from the graph
                for succ in sub_region.successors:
                    real_succs = list(self.graph_with_successors.successors(sub_region))
                    if succ not in updated_sub_region.successors:
                        # find the corresponding node in graph_with_successors
                        real_succ = next(iter(nn for nn in real_succs if nn.addr == succ.addr), None)
                        if real_succ is not None and real_succ not in self.graph:
                            self.graph_with_successors.remove_edge(sub_region, real_succ)
            self._replace_node_in_graph(self.graph_with_successors, sub_region, replace_with, edges_to_remove)

        self._node_to_replaced_regions[replace_with] = sub_region
        self._replaced_regions[sub_region] = replace_with

    def replace_region_with_region(self, sub_region: GraphRegion, replace_with: GraphRegion):
        if sub_region not in self.graph:
            l.error("The sub-region to replace must be in the current region. Note that this method is not recursive.")
            raise Exception

        if sub_region is self.head:
            self.head = replace_with.head

        # special case: a successor in replace_with.successors is a normal AIL block while the corresponding
        # successor in self.successors is a graph region (with the AIL block as its head). we handle this case here by
        # creating a new graph_with_successors for the replace_with region
        successor_map = {}
        if self.successors and any(succ not in self.successors for succ in replace_with.successors):
            for succ in replace_with.successors:
                if succ not in self.successors:
                    for succ_ in self.successors:
                        if isinstance(succ_, GraphRegion) and succ_.addr == succ.addr:
                            successor_map[succ] = succ_
        if successor_map:
            replace_with_graph_with_successors = networkx.DiGraph()
            for nn in replace_with.graph_with_successors:
                replace_with_graph_with_successors.add_node(successor_map.get(nn, nn))
            for n0, n1 in replace_with.graph_with_successors.edges:
                n0 = successor_map.get(n0, n0)
                n1 = successor_map.get(n1, n1)
                replace_with_graph_with_successors.add_edge(n0, n1)
        else:
            replace_with_graph_with_successors = replace_with.graph_with_successors

        self._replace_node_in_graph_with_subgraph(
            self.graph,
            self.successors,
            self.full_graph,
            sub_region,
            replace_with_graph_with_successors,
            replace_with.head,
        )
        if self.graph_with_successors is not None:
            self._replace_node_in_graph_with_subgraph(
                self.graph_with_successors,
                None,
                self.full_graph,
                sub_region,
                replace_with_graph_with_successors,
                replace_with.head,
            )

    @staticmethod
    def _replace_node_in_graph(graph: networkx.DiGraph, node, replace_with, removed_edges: set):
        in_edges = [(src, dst) for src, dst in graph.in_edges(node) if (src, dst) not in removed_edges]
        out_edges = [(src, dst) for src, dst in graph.out_edges(node) if (src, dst) not in removed_edges]

        graph.remove_node(node)
        graph.add_node(replace_with)

        for src, _ in in_edges:
            if src is node:
                graph.add_edge(replace_with, replace_with)
            else:
                graph.add_edge(src, replace_with)

        for _, dst in out_edges:
            if dst is node:
                graph.add_edge(replace_with, replace_with)
            else:
                graph.add_edge(replace_with, dst)

        assert node not in graph

    def _replace_node_in_graph_with_subgraph(
        self,
        graph: networkx.DiGraph,
        known_successors: list | None,
        reference_full_graph: networkx.DiGraph | None,
        node,
        sub_graph: networkx.DiGraph,
        sub_graph_head,
    ):
        in_edges = list(graph.in_edges(node))
        out_edges = list(graph.out_edges(node))

        graph.remove_node(node)
        sub_graph_nodes = [self._replaced_regions.get(nn, nn) for nn in sub_graph.nodes]
        sub_graph_edges = [
            (self._replaced_regions.get(src, src), self._replaced_regions.get(dst, dst)) for src, dst in sub_graph.edges
        ]

        for src, _ in in_edges:
            if src is node:
                graph.add_edge(sub_graph_head, sub_graph_head)
            else:
                graph.add_edge(src, sub_graph_head)

        for _, dst in out_edges:
            if dst is node:
                # ignore all self-loops
                continue
            if known_successors is not None and dst in known_successors:
                continue

            dst_in_subgraph = self._node_to_replaced_regions.get(dst, dst)

            # find the correct source
            if isinstance(dst_in_subgraph, GraphRegion) and dst_in_subgraph not in sub_graph:
                # GraphRegion.successors may not store GraphRegion objects. Instead, the heads of GraphRegion objects
                # are stored.
                dst_head = dst_in_subgraph
                while isinstance(dst_head, GraphRegion) and dst_head not in sub_graph:
                    dst_head = dst_head.head

                if dst_head not in sub_graph:
                    # unexpected: structuring failed and resulted in a bad sub_graph
                    l.warning(
                        "Node %r for node %r is not found in the sub graph at address %#x. Nodes may go missing.",
                        dst_head,
                        dst_in_subgraph,
                        sub_graph_head.addr,
                    )
                    continue

                for src in sub_graph.predecessors(dst_head):
                    graph.add_edge(src, dst)
                # replace the corresponding nodes in sub_graph_nodes and sub_graph_edges
                for i in range(len(sub_graph_nodes)):  # pylint:disable=consider-using-enumerate
                    if sub_graph_nodes[i] is dst_head:
                        sub_graph_nodes[i] = dst
                for i in range(len(sub_graph_edges)):  # pylint:disable=consider-using-enumerate
                    if sub_graph_edges[i][0] is dst_head:
                        sub_graph_edges[i] = (dst, sub_graph_edges[i][1])
                    if sub_graph_edges[i][1] is dst_head:
                        sub_graph_edges[i] = (sub_graph_edges[i][0], dst)
            else:
                if dst_in_subgraph in sub_graph:
                    for src in sub_graph.predecessors(dst_in_subgraph):
                        graph.add_edge(src, dst)
                elif reference_full_graph is not None and dst_in_subgraph in reference_full_graph:
                    for src in reference_full_graph.predecessors(dst_in_subgraph):
                        if src in graph:
                            graph.add_edge(src, dst)
                else:
                    # it may happen that the dst node does not exist in sub_graph
                    # fallback
                    l.info("Node dst is not found in sub_graph. Enter the fall back logic.")
                    for src in sub_graph.nodes:
                        if sub_graph.out_degree[src] == 0:
                            graph.add_edge(src, dst)

        graph.add_nodes_from(sub_graph_nodes)
        graph.add_edges_from(sub_graph_edges)
        # finally, remove all nodes from the graph in known_successors. they are only supposed to be in
        # graph_with_successors.
        if known_successors is not None:
            for nn in known_successors:
                if nn in graph:
                    graph.remove_node(nn)

        assert node not in graph
