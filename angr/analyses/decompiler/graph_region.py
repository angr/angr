
import logging
from typing import Optional, List

import networkx

from .structurer_nodes import MultiNode


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

    __slots__ = ('head', 'graph', 'successors', 'graph_with_successors', 'cyclic', )

    def __init__(self, head, graph, successors: Optional[list], graph_with_successors: networkx.DiGraph, cyclic):
        self.head = head
        self.graph = graph
        self.successors = successors
        # successors inside graph_with_successors should be treated as read-only. when deep-copying GraphRegion objects,
        # successors inside graph_with_successors are *not* deep copied. therefore, you should never modify any
        # successor node in graph_with_successors. to avoid potential programming errors, just treat
        # graph_with_successors as read-only.
        self.graph_with_successors: networkx.DiGraph = graph_with_successors
        self.cyclic = cyclic

    def __repr__(self):
        addrs: List[int] = [ ]
        s = ""
        if self.graph is None:
            # only head is available
            return "<GraphRegion %r>" % self.head

        for node in self.graph.nodes():
            if hasattr(node, 'addr'):
                addrs.append(node.addr)
        if addrs:
            s = ": %#x-%#x" % (min(addrs), max(addrs))

        return "<GraphRegion %r of %d nodes%s>" % (self.head, self.graph.number_of_nodes(), s)

    def recursive_copy(self):

        nodes_map = { }
        new_graph = self._recursive_copy(self.graph, nodes_map)

        if self.graph_with_successors is not None:
            successors = set(nodes_map.get(succ, succ) for succ in self.successors)
            # for performance reasons, successors that are only in graph_with_successors are not recursively copied
            new_graph_with_successors = self._recursive_copy(self.graph_with_successors, nodes_map,
                                                             ignored_nodes=successors)
        else:
            new_graph_with_successors = None
            successors = None

        return GraphRegion(nodes_map[self.head], new_graph, successors, new_graph_with_successors, self.cyclic)

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
                    new_node = node.recursive_copy()
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
        if type(obj) is GraphRegion:
            s = obj.dbg_print(ident=ident)
        else:
            s = " " * ident + str(obj)

        return s

    def dbg_print(self, ident=0):

        s = self.dbg_get_repr(self.head, ident=ident) + "\n"

        successors = list(self.graph.successors(self.head))
        if len(successors) == 2:
            left_kid, right_kid = successors
            s += " " * ident + "if (...) {\n" + \
                 self.dbg_get_repr(left_kid, ident=ident + 2) + "\n" + \
                 " " * ident + "}\n" + \
                 " " * ident + "else if (...) {\n" + \
                 self.dbg_get_repr(right_kid, ident=ident + 2) + "\n" + \
                 " " * ident + "}"
            # TODO: other nodes
        elif len(successors) == 1:
            s += self.dbg_get_repr(successors[0], ident=ident)

        return s

    def replace_region(self, sub_region, replace_with):

        if sub_region not in self.graph:
            l.error("The sub-region to replace must be in the current region. Note that this method is not recursive.")
            raise Exception()

        if sub_region is self.head:
            self.head = replace_with

        self._replace_node_in_graph(self.graph, sub_region, replace_with)
        if self.graph_with_successors is not None:
            self._replace_node_in_graph(self.graph_with_successors, sub_region, replace_with)

    @staticmethod
    def _replace_node_in_graph(graph: networkx.DiGraph, node, replace_with):

        in_edges = list(graph.in_edges(node))
        out_edges = list(graph.out_edges(node))

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
