# pylint:disable=consider-using-dict-items
from __future__ import annotations
from typing import Any
from collections import defaultdict

import networkx

from angr.utils.graph import shallow_reverse


class IncrementalDominators:
    """
    This class allows for incrementally updating dominators and post-dominators for graphs. The graph must only be
    modified by replacing nodes, not adding nodes or edges.
    """

    def __init__(self, graph: networkx.DiGraph, start, post: bool = False):
        self.graph = graph
        self.start = start
        self._post: bool = post  # calculate post-dominators if True
        self._pre: bool = not post  # calculate dominators

        self._doms: dict[Any, Any] = {}
        self._dfs: dict[Any, set[Any]] | None = None  # initialized on-demand
        self._inverted_dom_tree: dict[Any, Any] | None = None  # initialized on demand

        self._doms = self.init_doms()

    def init_doms(self) -> dict[Any, Any]:
        if self._post:
            t = shallow_reverse(self.graph)
            doms = networkx.immediate_dominators(t, self.start)
        else:
            doms = networkx.immediate_dominators(self.graph, self.start)
        return doms

    def init_dfs(self) -> dict[Any, set[Any]]:
        _pred = self.graph.predecessors if self._pre else self.graph.successors
        df: dict = {}
        for u in self._doms:
            _preds = list(_pred(u))  # type:ignore
            if len(_preds) >= 2:
                for v in _preds:
                    if v in self._doms:
                        while v is not self._doms[u]:
                            if v not in df:
                                df[v] = set()
                            df[v].add(u)
                            v = self._doms[v]
        return df

    def _update_inverted_domtree(self):
        # recalculate the dominators for dominatees of replaced nodes
        if self._inverted_dom_tree is None:
            self._inverted_dom_tree = defaultdict(list)
            for dtee, dtor in self._doms.items():
                self._inverted_dom_tree[dtor].append(dtee)

    def graph_updated(self, new_node: Any, replaced_nodes: set[Any], replaced_head: Any):
        self._update_inverted_domtree()
        assert self._inverted_dom_tree is not None

        # recalculate the dominators for impacted nodes
        new_dom = self._doms[replaced_head]
        while new_dom in replaced_nodes and new_dom is not self.start:
            new_dom = self._doms[new_dom]

        if self.start in replaced_nodes:
            self.start = new_node
        if new_dom in replaced_nodes:
            new_dom = new_node

        new_node_doms = []
        for rn in replaced_nodes:
            if rn not in self._inverted_dom_tree:
                continue
            for dtee in self._inverted_dom_tree[rn]:
                self._doms[dtee] = new_node
                new_node_doms.append(dtee)
        self._doms[new_node] = new_dom

        if self._dfs is not None:
            # update dominance frontiers
            if replaced_head in self._dfs:
                self._dfs[new_node] = self._dfs[replaced_head]
            for rn in replaced_nodes:
                if rn in self._dfs:
                    del self._dfs[rn]
                for df in self._dfs.values():
                    if rn in df:
                        df.remove(rn)
                        df.add(new_node)

        # keep inverted dom tree up-to-date
        self._inverted_dom_tree[new_dom].append(new_node)
        self._inverted_dom_tree[new_node] = new_node_doms
        for rn in replaced_nodes:
            if rn in self._doms:
                d = self._doms[rn]
                del self._doms[rn]
                self._inverted_dom_tree[d].remove(rn)
            if rn in self._inverted_dom_tree:
                del self._inverted_dom_tree[rn]

    def idom(self, node: Any) -> Any | None:
        """
        Get the immediate dominator of a given node.
        """

        return self._doms.get(node, None)

    def df(self, node: Any) -> set[Any]:
        """
        Generate the dominance frontier of a node.
        """
        if self._dfs is None:
            self._dfs = self.init_dfs()
        return self._dfs.get(node, set())

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

    def _debug_check(self):
        true_doms = self.init_doms()
        if len(true_doms) != len(self._doms):
            raise ValueError("dominators do not match")
        for k in true_doms:
            if true_doms[k] != self._doms[k]:
                print(f"{k!r}: {true_doms[k]!r} {self._doms[k]!r}")
                raise ValueError("dominators do not match")

        if self._dfs is not None:
            dfs = self.init_dfs()
            if len(dfs) != len(self._dfs):
                raise ValueError("dfs do not match")
            for k in dfs:
                if dfs[k] != self._dfs[k]:
                    print(f"{k!r}: {dfs[k]!r} {self._dfs[k]!r}")
                    raise ValueError("dfs do not match")
