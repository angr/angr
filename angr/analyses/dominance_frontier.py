from __future__ import annotations
from ..utils.graph import compute_dominance_frontier, Dominators
from .analysis import Analysis
from . import register_analysis


class DominanceFrontier(Analysis):
    """
    Computes the dominance frontier of all nodes in a function graph, and provides an easy-to-use interface for
    querying the frontier information.
    """

    def __init__(self, func, func_graph=None, entry=None, exception_edges=False):
        self.function = func
        self.func_graph = func_graph
        self.entry = entry
        self._exception_edges = exception_edges

        self.frontiers = None

        self._compute()

    def _get_graph(self):
        if self.func_graph is not None:
            return self.func_graph
        return self.function.graph_ex(exception_edges=self._exception_edges)

    def _compute(self):
        g = self._get_graph()

        if self.entry is not None:
            startpoint = self.entry
        else:
            if self.function.startpoint is None:
                # The function might be empty or is corrupted (maybe the object is created manually)
                raise TypeError(f"Startpoint of function {self.function!r} is None. Is this function empty?")

            if self.function.startpoint not in g:
                # find the actual start point
                startpoint = next(iter(nn for nn in g if nn.addr == self.function.startpoint.addr), None)
                if startpoint is None:
                    raise ValueError(
                        f"Cannot find the startpoint of function {self.function!r} in the given function graph."
                    )
            else:
                startpoint = self.function.startpoint

        # Compute the dominator tree
        doms = Dominators(g, startpoint)

        # Compute the dominance frontier
        dom_frontiers = compute_dominance_frontier(g, doms.dom)

        self.frontiers = dom_frontiers


register_analysis(DominanceFrontier, "DominanceFrontier")
