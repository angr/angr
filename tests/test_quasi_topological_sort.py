import networkx as nx
from hypothesis import given, example
import hypothesis.strategies as st
from hypothesis_networkx import graph_builder

from angr.analyses.cfg.cfg_utils import CFGUtils

def two_node_loop():
    g = nx.DiGraph()
    g.add_edge(0, 1)
    g.add_edge(1, 0)
    return g

def one_node():
    g = nx.DiGraph()
    g.add_node(0)
    return g

@given(graph_builder( # pylint: disable=no-value-for-parameter
    graph_type=nx.DiGraph,
    node_keys=st.integers(),
    min_nodes=1, max_nodes=20,
    min_edges=0, max_edges=None,
    self_loops=True,
    connected=True,
))
@example(one_node())
@example(two_node_loop())
def test_quasi_topological_sort(g):
    qua_top_sorted = CFGUtils.quasi_topological_sort_nodes(g)

    assert set(qua_top_sorted) == set(g.nodes())

    tc = nx.transitive_closure(g)

    reachable = lambda a, b: (a, b) in tc.edges()

    for i, node_i in enumerate(qua_top_sorted):
        for j, node_j in enumerate(qua_top_sorted):
            if i < j:
                assert not (reachable(node_j, node_i) and not reachable(node_i, node_j))
