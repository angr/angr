from ...cfg.cfg_utils import CFGUtils
from .graph import GraphVisitor


class FunctionGraphVisitor(GraphVisitor):
    """
    :param knowledge.Function func:
    """
    def __init__(self, func, graph=None):
        super(FunctionGraphVisitor, self).__init__()
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
