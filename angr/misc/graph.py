
def dfs_back_edges(graph, start_node):
    """
    Do a DFS traversal of the graph, and return with the back edges.

    Note: This is just a naive recursive implementation, feel free to replace it.
    I couldn't find anything in networkx to do this functionality. Although the
    name suggest it, but `dfs_labeled_edges` is doing something different.

    :param graph:       The graph to traverse.
    :param node:        The node where to start the traversal
    :returns:           An iterator of 'backward' edges
    """

    visited = set()
    finished = set()

    def _dfs_back_edges_core(node):
        visited.add(node)
        for child in iter(graph[node]):
            if child not in finished:
                if child in  visited:
                    yield node, child
                else:
                    for s,t in _dfs_back_edges_core(child):
                        yield s,t
        finished.add(node)

    for s,t in _dfs_back_edges_core(start_node):
        yield s,t

