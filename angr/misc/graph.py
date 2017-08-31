
import networkx


def shallow_reverse(g):
    """
    Make a shallow copy of a directional graph and reverse the edges. This is a workaround to solve the issue that one
    cannot easily make a shallow reversed copy of a graph in NetworkX 2, since networkx.reverse(copy=False) now returns
    a GraphView, and GraphViews are always read-only.

    :param networkx.DiGraph g:  The graph to reverse.
    :return:                    A new networkx.DiGraph that has all nodes and all edges of the original graph, with edges
                                reversed.
    """

    new_g = networkx.DiGraph()

    new_g.add_nodes_from(g.nodes())
    for src, dst, data in g.edges(data=True):
        new_g.add_edge(dst, src, **data)

    return new_g


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
