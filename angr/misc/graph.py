
import networkx


def shallow_reverse(g):
    """
    Make a shallow copy of a directional graph and reverse the edges. This is a workaround to solve the issue that one
    cannot easily make a shallow reversed copy of a graph in NetworkX 2, since networkx.reverse(copy=False) now returns
    a GraphView, and GraphViews are always read-only.

    :param networkx.DiGraph g:  The graph to reverse.
    :return:                    A new networkx.DiGraph that has all nodes and all edges of the original graph, with
                                edges reversed.
    """

    new_g = networkx.DiGraph()

    new_g.add_nodes_from(g.nodes())
    for src, dst, data in g.edges(data=True):
        new_g.add_edge(dst, src, **data)

    return new_g


#
# Dominance frontier
#

def compute_dominance_frontier(graph, postdom):
    """
    Compute a dominance frontier based on the given post-dominator tree.

    This implementation is based on figure 2 of paper An Efficient Method of Computing Static Single Assignment
    Form by Ron Cytron, etc.

    :param graph:   The graph where we want to compute the dominance frontier.
    :param postdom: The post-dominator tree
    :returns:       A dict of dominance frontier
    """

    DF = { }

    # Perform a post-order search on the post-dom tree
    for x in networkx.dfs_postorder_nodes(postdom):
        DF[x] = set()

        # local set
        for y in graph.successors(x):
            if x not in postdom.predecessors(y):
                DF[x].add(y)

        # up set
        if x is None:
            continue

        for z in postdom.successors(x):
            if z is x:
                continue
            if z not in DF:
                continue
            for y in DF[z]:
                if x not in list(postdom.predecessors(y)):
                    DF[x].add(y)

    return DF
