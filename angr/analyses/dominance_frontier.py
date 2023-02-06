from ..utils.graph import compute_dominance_frontier, Dominators
from .analysis import Analysis
from . import register_analysis


class DominanceFrontier(Analysis):
    """
    Computes the dominance frontier of all nodes in a function graph, and provides an easy-to-use interface for
    querying the frontier information.
    """

    def __init__(self, func, exception_edges=False):
        self.function = func
        self._exception_edges = exception_edges

        self.frontiers = None

        self._compute()

    def _get_graph(self):
        g = self.function.graph_ex(exception_edges=self._exception_edges)
        return g

    def _compute(self):
        g = self._get_graph()

        # Compute the dominator tree
        if self.function.startpoint is None:
            # The function might be empty or is corrupted (maybe the object is created manually)
            raise TypeError("Startpoint of function %s is None. Is this function empty?" % repr(self.function))
        doms = Dominators(g, self.function.startpoint)

        # Compute the dominance frontier
        dom_frontiers = compute_dominance_frontier(g, doms.dom)

        self.frontiers = dom_frontiers


register_analysis(DominanceFrontier, "DominanceFrontier")
