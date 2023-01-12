from ...cfg.cfg_utils import CFGUtils
from .graph import GraphVisitor


class CallGraphVisitor(GraphVisitor):
    """
    :param networkx.DiGraph callgraph:
    """

    def __init__(self, callgraph):
        super().__init__()
        self.callgraph = callgraph

        self.reset()

    def successors(self, node):
        return list(self.callgraph.successors(node))

    def predecessors(self, node):
        return list(self.callgraph.predecessors(node))

    def sort_nodes(self, nodes=None):
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.callgraph)

        if nodes is not None:
            sorted_nodes = [n for n in sorted_nodes if n in set(nodes)]

        return sorted_nodes
