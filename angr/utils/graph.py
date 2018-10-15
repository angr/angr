
from collections import defaultdict
import logging

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

    df = {}

    # Perform a post-order search on the post-dom tree
    for x in networkx.dfs_postorder_nodes(postdom):
        df[x] = set()

        # local set
        for y in graph.successors(x):
            if x not in postdom.predecessors(y):
                df[x].add(y)

        # up set
        if x is None:
            continue

        for z in postdom.successors(x):
            if z is x:
                continue
            if z not in df:
                continue
            for y in df[z]:
                if x not in list(postdom.predecessors(y)):
                    df[x].add(y)

    return df


#
# Post dominators
#


class TemporaryNode(object):
    """
    A temporary node.

    Used as the start node and end node in post-dominator tree generation. Also used in some test cases.
    """

    __slots__ = ['_label']

    def __init__(self, label):
        self._label = label

    def __repr__(self):
        return 'TemporaryNode[%s]' % self._label

    def __eq__(self, other):
        if isinstance(other, TemporaryNode) and other._label == self._label:
            return True
        return False

    def __hash__(self):
        return hash('%s' % self._label)


class ContainerNode(object):
    """
    A container node.

    Only used in post-dominator tree generation. We did this so we can set the index property without modifying the
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
            return self._obj == other._obj and self.index == other.index
        return False

    def __hash__(self):
        return 1  # I have genuinely no idea why defining a normal hash function makes everything break but it does


class PostDominators(object):

    def __init__(self, graph, entry_node, successors_func=None):

        self._l = logging.getLogger("utils.graph.post_dominators")
        self._graph_successors_func = successors_func

        # Temporary variables
        self._ancestor = None
        self._semi = None
        self._label = None

        # Output
        self.post_dom = None
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

        self.post_dom = networkx.DiGraph()  # The post-dom tree described in a directional graph
        for i in range(1, len(vertices)):
            if dom[i] is not None and vertices[i] is not None:
                self.post_dom.add_edge(dom[i].obj, vertices[i].obj)

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
                # Add an edge between this node and our start node
                new_graph.add_edge(start_node, container_node)

            for s in successors:
                if s in container_nodes:
                    container_s = container_nodes[s]
                else:
                    container_s = ContainerNode(s)
                    container_nodes[s] = container_s
                new_graph.add_edge(container_s, container_node)  # Reversed
                if container_s not in traversed_nodes:
                    queue.append(s)

        # Add a start node and an end node
        new_graph.add_edge(container_nodes[n], ContainerNode(TemporaryNode("end_node")))

        all_nodes_count = len(traversed_nodes) + 2  # A start node and an end node
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
