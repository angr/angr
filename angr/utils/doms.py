from __future__ import annotations
from typing import Any

import networkx


class IncrementalDominators:
    """
    This class implements a simple algorithm that incrementally calculates dominators and post-dominators for acyclic
    graphs.

    The graph must only be modified by replacing or removing nodes, not adding nodes or edges.
    """

    def __init__(self, graph: networkx.DiGraph, start, post: bool = False):
        self.graph = graph
        self.start = start
        self._post: bool = post  # calculate dominators
        self._pre: bool = not post  # calculate post-dominators

        self._idepths: dict[Any, int] = {start: 0}

    def idepth(self, node: Any) -> int:
        """
        Get the immediate dominator or post-dominator depth of a node.
        """

        assert node in self.graph
        if node is self.start:
            return 0
        if node not in self._idepths:
            _preds = self.graph.predecessors(node) if self._pre else self.graph.successors(node)
            preds = [p for p in _preds if p is not node]
            self._idepths[node] = 0 if not preds else max(self.idepth(p) for p in preds) + 1
        return self._idepths[node]

    def idom_lca(self, node: Any, rhs: Any) -> Any | None:
        if rhs is None:
            return node
        lhs = node
        while lhs is not rhs:
            comp = self.idepth(lhs) - self.idepth(rhs)
            if comp >= 0:
                lhs = self.idom(lhs) if lhs is not self.start else lhs
            if comp <= 0:
                rhs = self.idom(rhs) if rhs is not self.start else rhs
        return lhs

    def idom(self, node: Any) -> Any | None:
        """
        Get the immediate dominator of a given node.
        """

        if node not in self.graph:
            return None
        pred_func = self.graph.predecessors if self._pre else self.graph.successors
        preds = list(pred_func(node))  # type: ignore
        if not preds:
            return None
        if len(preds) == 1:
            return preds[0]
        lca = preds[0]
        for pred in preds[1:]:
            if pred is node:
                continue
            lca = self.idom_lca(pred, lca)
        return lca

    def df(self, node: Any):
        """
        Generate the dominance frontier of a node.
        """
        df = set()
        _succ = self.graph.successors if self._pre else self.graph.predecessors
        queue = list(_succ(node))  # type: ignore
        while queue:
            u = queue.pop(0)
            if self.idom(u) is not node:
                df.add(u)
            else:
                queue += list(_succ(u))  # type: ignore
        return df

    def dominates(self, dominator_node: Any, node: Any) -> bool:
        """
        Tests if dominator_node dominates (or post-dominates) node.
        """

        n = node
        while n:
            if n is dominator_node:
                return True
            d = self.idom(n)
            n = d if d is not None and n is not d else None
        return False
