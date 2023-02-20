from typing import List, Tuple
import logging

import networkx

from ....utils.graph import dfs_back_edges
from ...cfg.cfg_utils import CFGUtils
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

    def resume_with_new_graph(self, graph: networkx.DiGraph) -> None:
        """
        We can only reasonably reuse existing results if the node index of the already traversed nodes are the same as
        the ones from the new graph. Otherwise, we always restart.
        """
        # update the graph
        self.graph = graph

        must_restart = False
        sorted_nodes = list(self.sort_nodes())
        for i, n in enumerate(sorted_nodes):
            if i >= self._node_idx:
                break
            if n not in self._node_to_index:
                must_restart = True
                break
            if self._node_to_index[n] != i:
                must_restart = True
                break

        if must_restart:
            _l.debug("Failed to resume for function %r.", self.function)
            self.reset()
            return

        # update related data structures
        self._sorted_nodes = self._sorted_nodes[: self._node_idx]
        self._sorted_nodes += sorted_nodes[self._node_idx :]
        self._nodes_set |= set(sorted_nodes[self._node_idx :])
        for i, n in enumerate(sorted_nodes):
            if i >= self._node_idx:
                self._node_to_index[n] = i

    def successors(self, node):
        return list(self.graph.successors(node))

    def predecessors(self, node):
        return list(self.graph.predecessors(node))

    def sort_nodes(self, nodes=None):
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.graph)

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
