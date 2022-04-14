from typing import List, Tuple

from ....utils.graph import dfs_back_edges
from ...cfg.cfg_utils import CFGUtils
from .graph import GraphVisitor, NodeType


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

    def successors(self, node):
        return list(self.graph.successors(node))

    def predecessors(self, node):
        return list(self.graph.predecessors(node))

    def sort_nodes(self, nodes=None):
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.graph)

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes

    def back_edges(self) -> List[Tuple[NodeType,NodeType]]:
        start_nodes = [ node for node in self.graph if node.addr == self.function.addr ]
        if not start_nodes:
            start_nodes = [ node for node in self.graph if self.graph.in_degree(node) == 0]

        if not start_nodes:
            raise NotImplementedError()

        start_node = start_nodes[0]
        return list(dfs_back_edges(self.graph, start_node))
