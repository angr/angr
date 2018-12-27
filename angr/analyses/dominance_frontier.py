
import networkx

from ..utils.graph import compute_dominance_frontier, Dominators
from .analysis import Analysis
from . import register_analysis


class DominanceFrontier(Analysis):
    """
    Computes the dominance frontier of all nodes in a function graph, and provides an easy-to-use interface for
    querying the frontier information.
    """

    def __init__(self, func):
        self.function = func

        self.frontiers = None

        self._compute()

    def _get_graph(self):

        g = networkx.DiGraph(self.function.graph)
        return g

    def _compute(self):

        g = self._get_graph()

        # Compute the dominator tree
        doms = Dominators(g, self.function.startpoint)

        # Compute the dominance frontier
        dom_frontiers = compute_dominance_frontier(g, doms.dom)

        self.frontiers = dom_frontiers


register_analysis(DominanceFrontier, "DominanceFrontier")
