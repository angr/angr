#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
"""The Rust ports in angr.rustylib.graph_utils against their Python originals on random graphs."""

from __future__ import annotations

import random
import unittest

import networkx as nx

from angr.utils.graph import GraphUtils


class N:
    """An addressed node; distinct (addr, idx) pairs give distinct sort keys."""

    __slots__ = ("addr", "idx")

    def __init__(self, addr: int, idx: int | None = None):
        self.addr = addr
        self.idx = idx

    def __eq__(self, other):
        return isinstance(other, N) and other.addr == self.addr and other.idx == self.idx

    def __hash__(self):
        return hash((N, self.addr, self.idx))

    def __repr__(self):
        return f"N({self.addr:#x}, {self.idx})"


class M(N):
    """Same address space, different type name: ties on (addr, idx) are broken by the type name."""


def random_graph(rng: random.Random, n: int) -> nx.DiGraph:
    nodes: list[N] = []
    for i in range(n):
        addr = 0x400000 + rng.randrange(n * 2) * 4
        cls = M if rng.random() < 0.15 else N
        node = cls(addr, rng.randrange(3) if rng.random() < 0.3 else None)
        if node not in nodes:
            nodes.append(node)
    g = nx.DiGraph()
    g.add_nodes_from(nodes)
    m = len(nodes)
    for _ in range(rng.randint(m // 2, 3 * m)):
        g.add_edge(rng.choice(nodes), rng.choice(nodes))
    # make sure every graph has loops, a self loop and unreachable nodes
    for _ in range(2):
        a, b, c = rng.choice(nodes), rng.choice(nodes), rng.choice(nodes)
        g.add_edge(a, b)
        g.add_edge(b, c)
        g.add_edge(c, a)
    g.add_edge(nodes[-1], nodes[-1])
    return g


class TestGraphUtilsRust(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(0x5EED)
        self.graphs = [random_graph(self.rng, self.rng.randint(2, 60)) for _ in range(120)]

    def test_quasi_topological_sort_nodes(self):
        for g in self.graphs:
            nodes = list(g)
            assert GraphUtils.quasi_topological_sort_nodes(g) == GraphUtils._quasi_topological_sort_nodes_py(g)
            # one candidate: with several candidates in one SCC the Python version picks by set-iteration order
            heads = [self.rng.choice(nodes)]
            subset = self.rng.sample(nodes, len(nodes) // 2)
            m_rust: dict = {}
            m_py: dict = {}
            r = GraphUtils.quasi_topological_sort_nodes(g, nodes=subset, loop_heads=heads, scc_membership=m_rust)
            p = GraphUtils._quasi_topological_sort_nodes_py(g, nodes=subset, loop_heads=heads, scc_membership=m_py)
            assert r == p
            assert m_rust == m_py

    def test_quasi_topological_sort_nodes_panic_mode(self):
        for _ in range(20):
            n = self.rng.randint(8, 30)
            nodes = [N(0x1000 + 4 * i) for i in range(n)]
            g = nx.DiGraph()
            g.add_nodes_from(nodes)
            for _ in range(n * 3):
                g.add_edge(self.rng.choice(nodes), self.rng.choice(nodes))
            r = GraphUtils.quasi_topological_sort_nodes(g, panic_mode_threshold=4)
            p = GraphUtils._quasi_topological_sort_nodes_py(g, panic_mode_threshold=4)
            assert r == p

    def test_quasi_topological_sort_nodes_python_fallback(self):
        g = nx.DiGraph([("a", "b"), ("b", "c"), ("c", "a"), ("c", "d"), ("d", "e"), ("e", "d")])
        assert GraphUtils.quasi_topological_sort_nodes(g) == GraphUtils._quasi_topological_sort_nodes_py(g)
        assert GraphUtils.quasi_topological_sort_nodes(g) == ["a", "b", "c", "d", "e"]


if __name__ == "__main__":
    unittest.main()
