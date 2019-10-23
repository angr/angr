from ...cfg.cfg_utils import CFGUtils
from .graph import GraphVisitor


class LoopVisitor(GraphVisitor):
    """
    :param angr.analyses.loopfinder.Loop loop: The loop to visit.
    """
    def __init__(self, loop):
        super(LoopVisitor, self).__init__()
        self.loop = loop

        self.reset()

    def successors(self, node):
        return self.loop.graph.successors(node)

    def predecessors(self, node):
        return self.loop.graph.predecessors(node)

    def sort_nodes(self, nodes=None):
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.loop.graph)

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes
