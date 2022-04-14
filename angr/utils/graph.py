
from collections import defaultdict
import logging

import networkx


def shallow_reverse(g) -> networkx.DiGraph:
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
                if child in visited:
                    yield node, child
                else:
                    for s,t in _dfs_back_edges_core(child):
                        yield s,t
        finished.add(node)

    for s,t in _dfs_back_edges_core(start_node):
        yield s,t


def subgraph_between_nodes(graph, source, frontier, include_frontier=False):
    """
    For a directed graph, return a subgraph that includes all nodes going from a source node to a target node.

    :param networkx.DiGraph graph:  The directed graph.
    :param source:                  The source node.
    :param list frontier:           A collection of target nodes.
    :param bool include_frontier:   Should nodes in frontier be included in the subgraph.
    :return:                        A subgraph.
    :rtype:                         networkx.DiGraph
    """

    graph = networkx.DiGraph(graph)  # make a copy
    for pred in list(graph.predecessors(source)):
        # make sure we cannot go from any other node to the source node
        graph.remove_edge(pred, source)

    g0 = networkx.DiGraph()

    if source not in graph or any(node not in graph for node in frontier):
        raise KeyError("Source node or frontier nodes are not in the source graph.")

    # BFS on graph and add new nodes to g0
    queue = [ source ]
    traversed = set()

    frontier = set(frontier)

    while queue:
        node = queue.pop(0)
        traversed.add(node)

        for _, succ, data in graph.out_edges(node, data=True):
            g0.add_edge(node, succ, **data)
            if succ in traversed or succ in frontier:
                continue
            for frontier_node in frontier:
                if networkx.has_path(graph, succ, frontier_node):
                    queue.append(succ)
                    break

    # recursively remove all nodes that have less than two neighbors
    to_remove = [ n for n in g0.nodes() if n not in frontier and n is not source and (g0.out_degree[n] == 0 or g0.in_degree[n] == 0) ]
    while to_remove:
        g0.remove_nodes_from(to_remove)
        to_remove = [ n for n in g0.nodes() if n not in frontier and n is not source and (g0.out_degree[n] == 0 or g0.in_degree[n] == 0) ]

    if not include_frontier:
        # remove the frontier nodes
        g0.remove_nodes_from(frontier)

    return g0


def dominates(idom, dominator_node, node):
    n = node
    while n:
        if n == dominator_node:
            return True
        if n in idom and n != idom[n]:
            n = idom[n]
        else:
            n = None
    return False

#
# Dominance frontier
#

def compute_dominance_frontier(graph, domtree):
    """
    Compute a dominance frontier based on the given post-dominator tree.

    This implementation is based on figure 2 of paper An Efficient Method of Computing Static Single Assignment
    Form by Ron Cytron, etc.

    :param graph:   The graph where we want to compute the dominance frontier.
    :param domtree: The dominator tree
    :returns:       A dict of dominance frontier
    """

    df = {}

    # Perform a post-order search on the dominator tree
    for x in networkx.dfs_postorder_nodes(domtree):

        if x not in graph:
            # Skip nodes that are not in the graph
            continue

        df[x] = set()

        # local set
        for y in graph.successors(x):
            if x not in domtree.predecessors(y):
                df[x].add(y)

        # up set
        if x is None:
            continue

        for z in domtree.successors(x):
            if z is x:
                continue
            if z not in df:
                continue
            for y in df[z]:
                if x not in list(domtree.predecessors(y)):
                    df[x].add(y)

    return df


#
# Dominators and post-dominators
#


class TemporaryNode:
    """
    A temporary node.

    Used as the start node and end node in post-dominator tree generation. Also used in some test cases.
    """

    __slots__ = ['_label']

    def __init__(self, label):
        self._label = label

    def __repr__(self):
        return 'TN[%s]' % self._label

    def __eq__(self, other):
        if isinstance(other, TemporaryNode) and other._label == self._label:
            return True
        return False

    def __hash__(self):
        return hash(('TemporaryNode', self._label))


class ContainerNode:
    """
    A container node.

    Only used in dominator tree generation. We did this so we can set the index property without modifying the
    original object.
    """

    __slots__ = ['_obj', 'index']

    def __init__(self, obj):
        self._obj = obj
        self.index = None

    @property
    def obj(self):
        return self._obj

    def __eq__(self, other):
        if isinstance(other, ContainerNode):
            return self._obj is other._obj
        return False

    def __hash__(self):
        return hash(('CN', self._obj))

    def __repr__(self):
        return "CN[%s]" % repr(self._obj)


class Dominators:
    dom: networkx.DiGraph

    def __init__(self, graph, entry_node, successors_func=None, reverse=False):

        self._l = logging.getLogger("utils.graph.dominators")
        self._graph_successors_func = successors_func

        self._reverse = reverse  # Set it to True to generate a post-dominator tree.

        # Temporary variables
        self._ancestor = None
        self._semi = None
        self._label = None

        # Output
        self.dom = None  # type: ignore # this is guaranteed to be not null after the __init__ returns
        self.prepared_graph = None

        self._construct(graph, entry_node)

    def _graph_successors(self, graph, node):
        """
        Return the successors of a node in the graph.
        This method can be overriden in case there are special requirements with the graph and the successors. For
        example, when we are dealing with a control flow graph, we may not want to get the FakeRet successors.

        :param graph: The graph.
        :param node:  The node of which we want to get the successors.
        :return:      An iterator of successors.
        :rtype:       iter
        """

        if self._graph_successors_func is not None:
            return self._graph_successors_func(graph, node)

        return graph.successors(node)

    def _construct(self, graph, entry_node):
        """
        Find post-dominators for each node in the graph.

        This implementation is based on paper A Fast Algorithm for Finding Dominators in a Flow Graph by Thomas
        Lengauer and Robert E. Tarjan from Stanford University, ACM Transactions on Programming Languages and Systems,
        Vol. 1, No. 1, July 1979
        """

        # Step 1

        _prepared_graph, vertices, parent = self._prepare_graph(graph, entry_node)
        # vertices is a list of ContainerNode instances
        # parent is a dict storing the mapping from ContainerNode to ContainerNode
        # Each node in prepared_graph is a ContainerNode instance

        bucket = defaultdict(set)
        dom = [None] * (len(vertices))
        self._ancestor = [None] * (len(vertices) + 1)

        for i in range(len(vertices) - 1, 0, -1):
            w = vertices[i]

            # Step 2
            if w not in parent:
                # It's one of the start nodes
                continue

            predecessors = _prepared_graph.predecessors(w)
            for v in predecessors:
                u = self._pd_eval(v)
                if self._semi[u.index].index < self._semi[w.index].index:
                    self._semi[w.index] = self._semi[u.index]

            bucket[vertices[self._semi[w.index].index].index].add(w)

            self._pd_link(parent[w], w)

            # Step 3
            for v in bucket[parent[w].index]:
                u = self._pd_eval(v)
                if self._semi[u.index].index < self._semi[v.index].index:
                    dom[v.index] = u
                else:
                    dom[v.index] = parent[w]

            bucket[parent[w].index].clear()

        for i in range(1, len(vertices)):
            w = vertices[i]
            if w not in parent:
                continue
            if dom[w.index].index != vertices[self._semi[w.index].index].index:
                dom[w.index] = dom[dom[w.index].index]

        self.dom = networkx.DiGraph()  # The post-dom tree described in a directional graph
        for i in range(1, len(vertices)):
            if dom[i] is not None and vertices[i] is not None:
                self.dom.add_edge(dom[i].obj, vertices[i].obj)

        # Output
        self.prepared_graph = _prepared_graph

    def _prepare_graph(self, graph, entry):

        # We want to reverse the graph, and label each node according to its order in a DFS
        new_graph = networkx.DiGraph()

        n = entry

        queue = [n]
        start_node = TemporaryNode("start_node")
        # Put the start_node into a Container as well
        start_node = ContainerNode(start_node)
        # Create the end_node, too
        end_node = ContainerNode(TemporaryNode("end_node"))

        container_nodes = {}

        traversed_nodes = set()
        while queue:
            node = queue.pop()

            successors = list(self._graph_successors(graph, node))

            # Put it into a container
            if node in container_nodes:
                container_node = container_nodes[node]
            else:
                container_node = ContainerNode(node)
                container_nodes[node] = container_node

            traversed_nodes.add(container_node)

            if len(successors) == 0:
                # Note that this condition may never be satisfied if there is no real "end node" in the graph: the graph
                # may end with a loop.
                if self._reverse:
                    # Add an edge between the start node and this node
                    new_graph.add_edge(start_node, container_node)
                else:
                    # Add an edge between our this node and end node
                    new_graph.add_edge(container_node, end_node)

            for s in successors:
                if s in container_nodes:
                    container_s = container_nodes[s]
                else:
                    container_s = ContainerNode(s)
                    container_nodes[s] = container_s
                if self._reverse:
                    new_graph.add_edge(container_s, container_node)  # Reversed
                else:
                    new_graph.add_edge(container_node, container_s)  # Reversed
                if container_s not in traversed_nodes:
                    queue.append(s)

        if self._reverse:
            # Add the end node
            new_graph.add_edge(container_nodes[n], end_node)
        else:
            # Add the start node
            new_graph.add_edge(start_node, container_nodes[n])

        all_nodes_count = new_graph.number_of_nodes()
        self._l.debug("There should be %d nodes in all", all_nodes_count)
        counter = 0
        vertices = [ContainerNode("placeholder")]
        scanned_nodes = set()
        parent = {}
        while True:
            # DFS from the current start node
            stack = [start_node]
            while len(stack) > 0:
                node = stack.pop()
                counter += 1

                # Mark it as scanned
                scanned_nodes.add(node)

                # Put the container node into vertices list
                vertices.append(node)

                # Put each successors into the stack
                successors = new_graph.successors(node)

                # Set the index property of it
                node.index = counter

                for s in successors:
                    if s not in scanned_nodes:
                        stack.append(s)
                        parent[s] = node
                        scanned_nodes.add(s)

            if counter >= all_nodes_count:
                break

            self._l.debug("%d nodes are left out during the DFS. They must formed a cycle themselves.",
                          all_nodes_count - counter)
            # Find those nodes
            leftovers = [s for s in traversed_nodes if s not in scanned_nodes]
            new_graph.add_edge(start_node, leftovers[0])
            # We have to start over...
            counter = 0
            parent = {}
            scanned_nodes = set()
            vertices = [ContainerNode("placeholder")]

        self._semi = vertices[::]
        self._label = vertices[::]

        return new_graph, vertices, parent

    def _pd_link(self, v, w):
        self._ancestor[w.index] = v

    def _pd_eval(self, v):
        if self._ancestor[v.index] is None:
            return v
        else:
            self._pd_compress(v)
            return self._label[v.index]

    def _pd_compress(self, v):
        if self._ancestor[self._ancestor[v.index].index] is not None:
            self._pd_compress(self._ancestor[v.index])
            if self._semi[self._label[self._ancestor[v.index].index].index].index < \
                    self._semi[self._label[v.index].index].index:
                self._label[v.index] = self._label[self._ancestor[v.index].index]
            self._ancestor[v.index] = self._ancestor[self._ancestor[v.index].index]


class PostDominators(Dominators):
    def __init__(self, graph, entry_node, successors_func=None):
        super().__init__(graph, entry_node, successors_func=successors_func, reverse=True)

    @property
    def post_dom(self) -> networkx.DiGraph:
        return self.dom
