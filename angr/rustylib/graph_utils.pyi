from collections.abc import Mapping, Sequence
from typing import Any

def quasi_topological_sort_nodes(
    successors: Mapping[Any, Mapping[Any, Any]],
    loop_heads: Sequence[Any] | None = None,
    panic_mode_threshold: int = 3000,
    scc_membership: bool = False,
) -> tuple[list[Any], list[tuple[Any, int]] | None]:
    """
    GraphUtils.quasi_topological_sort_nodes over a graph's successor mapping (``DiGraph._succ``: node -> successor ->
    edge data; nodes in iteration order, successors in adjacency order). Nodes sort by their ``addr``/``idx``/type
    name like GraphUtils.sort_node.

    :arg loop_heads: Nodes to prefer as the loop head of their strongly connected component.
    :arg panic_mode_threshold: Component size above which dense components lose back edges before being sorted.
    :arg scc_membership: Also return (node, index of its non-trivial strongly connected component) pairs.
    :returns: The ordered nodes and the membership pairs (None unless requested).
    :raises TypeError: If a node has neither an integer ``addr`` nor is an integer itself (callers fall back to Python).
    """

def dfs_postorder_nodes_deterministic(successors: Mapping[Any, Mapping[Any, Any]], sources: Sequence[Any]) -> list[Any]:
    """
    GraphUtils.dfs_postorder_nodes_deterministic_multi over a graph's successor mapping; a single source gives the
    single-source traversal.

    :raises KeyError: If a source is not a node of the graph.
    """
