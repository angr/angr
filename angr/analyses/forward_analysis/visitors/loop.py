from __future__ import annotations
from angr.utils.graph import GraphUtils
from .graph import GraphVisitor


class LoopVisitor(GraphVisitor):
    """
    :param angr.analyses.loopfinder.Loop loop: The loop to visit.
    """

    def __init__(self, loop):
        super().__init__()
        self.loop = loop

        self.reset()

    def successors(self, node):
        return self.loop.graph.successors(node)

    def predecessors(self, node):
        return self.loop.graph.predecessors(node)

    def sort_nodes(self, nodes=None):
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self.loop.graph)

        if nodes is not None:
            sorted_nodes = [n for n in sorted_nodes if n in set(nodes)]

        return sorted_nodes
