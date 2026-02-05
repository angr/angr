from __future__ import annotations
from typing import Generic, TypeVar, overload

import networkx
from angr.codenode import CodeNode
from angr.knowledge_plugins.functions.function import Function
from angr.utils.graph import compute_dominance_frontier, Dominators

T_co = TypeVar("T_co", covariant=True)


class DominanceFrontier(Generic[T_co]):
    """
    Computes the dominance frontier of all nodes in a function graph, and provides an easy-to-use interface for
    querying the frontier information.
    """

    @overload
    def __init__(
        self, func: Function, func_graph: networkx.DiGraph[T_co], entry: T_co, exception_edges: bool = False
    ): ...
    @overload
    def __init__(
        self: DominanceFrontier[CodeNode],
        func: Function,
        func_graph: networkx.DiGraph[CodeNode] | None = None,
        entry: CodeNode | None = None,
        exception_edges: bool = False,
    ): ...

    def __init__(
        self, func: Function, func_graph: networkx.DiGraph[T_co] | None = None, entry=None, exception_edges=False
    ):  # type: ignore
        self.function = func
        self.func_graph = func_graph
        self.entry = entry
        self._exception_edges = exception_edges

        self.frontiers = self._compute()

    def _get_graph(self) -> networkx.DiGraph[T_co]:
        if self.func_graph is not None:
            return self.func_graph
        return self.function.graph_ex(exception_edges=self._exception_edges)  # type: ignore

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
                startpoint = next(iter(nn for nn in g if nn.addr == self.function.startpoint.addr), None)  # type: ignore
                if startpoint is None:
                    raise ValueError(
                        f"Cannot find the startpoint of function {self.function!r} in the given function graph."
                    )
            else:
                startpoint = self.function.startpoint

        # Compute the dominator tree
        doms: Dominators[T_co] = Dominators(g, startpoint)  # type: ignore

        # Compute the dominance frontier
        return compute_dominance_frontier(g, doms.dom)


def calculate_iterated_dominace_frontier_set(frontiers: dict, blocks: set) -> set:
    last_frontier: set | None = None
    while True:
        frontier = set()
        for b in blocks:
            if b in frontiers:
                frontier |= frontiers[b]
        if last_frontier is not None and last_frontier == frontier:
            break
        last_frontier = frontier
        blocks |= frontier
    return last_frontier
