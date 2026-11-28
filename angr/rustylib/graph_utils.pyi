from collections.abc import Mapping, Sequence
from typing import Any

def quasi_topological_sort_nodes(
    successors: Mapping[Any, Mapping[Any, Any]],
    loop_heads: Sequence[Any] | None = None,
    panic_mode_threshold: int = 3000,
    scc_membership: bool = False,
) -> tuple[list[Any], list[tuple[Any, int]] | None]:
    """
    The Rust port of `GraphUtils.quasi_topological_sort_nodes`.

    This function takes the successor mapping of a graph, which is `DiGraph._succ`.
    Nodes are sorted by `addr`, `idx`, and the type name, in the same way as `GraphUtils.sort_node`.

    :arg loop_heads: Nodes that we prefer as the loop heads of their strongly connected components.
    :arg panic_mode_threshold: Threshold of nodes in an SCC to begin aggressively removing edges.
    :arg scc_membership: True if we also return the non-trivial strongly connected component of each node.
    :returns: A list of ordered nodes, and a list of pairs of a node and the index of its component if requested.
    :raises TypeError: If a node does not have an integer address.
    """

def dfs_postorder_nodes_deterministic(successors: Mapping[Any, Mapping[Any, Any]], sources: Sequence[Any]) -> list[Any]:
    """
    The Rust port of `GraphUtils.dfs_postorder_nodes_deterministic_multi`.

    This function takes the successor mapping of a graph.

    :raises KeyError: If a source is not a node of the graph.
    """

def dfs_back_edges(
    successors: Mapping[Any, Mapping[Any, Any]], start: Any, visit_all_nodes: bool = False
) -> list[tuple[Any, Any]]:
    """
    The Rust port of `angr.utils.graph.dfs_back_edges`.

    This function takes the successor mapping of a graph and returns the back edges in traversal order.

    :raises KeyError: If `start` is not a node of the graph.
    """

def immediate_dominators(successors: Mapping[Any, Mapping[Any, Any]], start: Any) -> dict[Any, Any]:
    """
    The Rust port of `networkx.immediate_dominators`.

    This function takes the successor mapping of a graph and returns the immediate dominator of every node that is
    reachable from `start`.
    The keys of the returned dict are in the same order as the keys that networkx returns.

    :raises KeyError: If `start` is not a node of the graph.
    """
