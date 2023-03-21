from typing import List, Tuple
import logging

import networkx

from angr.utils.graph import dfs_back_edges, GraphUtils
from .graph import GraphVisitor, NodeType

_l = logging.getLogger(__name__)


class FunctionGraphVisitor(GraphVisitor):
    """
    :param knowledge.Function func:
    """

    def __init__(self, func, graph=None):
        super().__init__()
        self.function = func

        if graph is None:
            self.graph = self.function.graph
        else:
            self.graph = graph

        self.reset()

    def resume_with_new_graph(self, graph: networkx.DiGraph) -> bool:
        """
        We can only reasonably reuse existing results if the node index of the already traversed nodes are the same as
        the ones from the new graph. Otherwise, we always restart.

        :return:    True if we are resuming, False if reset() is called.
        """
        # update the graph
        self.graph = graph

        must_restart = False
        new_sorted_nodes = list(self.sort_nodes())
        # check if new sorted_nodes is an extension of the existing sorted_nodes
        if len(new_sorted_nodes) < len(self._sorted_nodes):
            must_restart = True
        else:
            must_restart = not new_sorted_nodes[: len(self._sorted_nodes)] == self._sorted_nodes

        if must_restart:
            _l.debug("Cannot resume for function %r with the new graph.", self.function)
            self.reset()
            return False

        # update related data structures
        for i, n in enumerate(new_sorted_nodes):
            if i >= len(self._sorted_nodes):
                self._node_to_index[n] = i
        # update worklist and nodes_set
        for n in new_sorted_nodes[len(self._sorted_nodes) :]:
            self.revisit_node(n)
        # update sorted_nodes in the end
        self._sorted_nodes = new_sorted_nodes

        return True

    def successors(self, node):
        return list(self.graph.successors(node))

    def predecessors(self, node):
        return list(self.graph.predecessors(node))

    def sort_nodes(self, nodes=None):
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self.graph)

        if nodes is not None:
            sorted_nodes = [n for n in sorted_nodes if n in set(nodes)]

        return sorted_nodes

    def back_edges(self) -> List[Tuple[NodeType, NodeType]]:
        start_nodes = [node for node in self.graph if node.addr == self.function.addr]
        if not start_nodes:
            start_nodes = [node for node in self.graph if self.graph.in_degree(node) == 0]

        if not start_nodes:
            raise NotImplementedError()

        start_node = start_nodes[0]
        return list(dfs_back_edges(self.graph, start_node))
