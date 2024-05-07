from collections import defaultdict
import logging

import networkx
import networkx.algorithms


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


def inverted_idoms(graph: networkx.DiGraph) -> tuple[networkx.DiGraph, dict | None]:
    """
    Invert the given graph and generate the immediate dominator tree on the inverted graph. This is useful for
    computing post-dominators.

    :param graph:   The graph to invert and generate immediate dominator tree for.
    :return:        A tuple of the inverted graph and the immediate dominator tree.
    """

    end_nodes = {n for n in graph.nodes() if graph.out_degree(n) == 0}
    inverted_graph: networkx.DiGraph = shallow_reverse(graph)
    if end_nodes:
        if len(end_nodes) > 1:
            # make sure there is only one end node
            dummy_node = "DUMMY_NODE"
            for end_node in end_nodes:
                inverted_graph.add_edge(dummy_node, end_node)
            endnode = dummy_node
        else:
            endnode = next(iter(end_nodes))  # pick the end node

        idoms = networkx.immediate_dominators(inverted_graph, endnode)
    else:
        idoms = None
    return inverted_graph, idoms


def to_acyclic_graph(
    graph: networkx.DiGraph, ordered_nodes: list | None = None, loop_heads: list | None = None
) -> networkx.DiGraph:
    """
    Convert a given DiGraph into an acyclic graph.

    :param graph:           The graph to convert.
    :param ordered_nodes:   A list of nodes sorted in a topological order.
    :param loop_heads:      A list of known loop head nodes.
    :return:                The converted acyclic graph.
    """

    if ordered_nodes is None:
        # take the quasi-topological order of the graph
        ordered_nodes = GraphUtils.quasi_topological_sort_nodes(graph, loop_heads=loop_heads)

    acyclic_graph = networkx.DiGraph()

    # add each node and its edge into the graph
    visited = set()
    for node in ordered_nodes:
        visited.add(node)
        acyclic_graph.add_node(node)
        for successor in graph.successors(node):
            if successor not in visited:
                acyclic_graph.add_edge(node, successor)

    return acyclic_graph


def dfs_back_edges(graph, start_node):
    """
    Perform an iterative DFS traversal of the graph, returning back edges.

    :param graph:       The graph to traverse.
    :param start_node:  The node where to start the traversal.
    :returns:           An iterator of 'backward' edges.
    """
    if start_node not in graph:
        return  # Ensures that the start node is in the graph

    visited = set()  # Tracks visited nodes
    finished = set()  # Tracks nodes whose descendants are fully explored
    stack = [(start_node, iter(graph[start_node]))]

    while stack:
        node, children = stack[-1]
        visited.add(node)

        try:
            child = next(children)
            if child in visited:
                if child not in finished:
                    yield node, child  # Found a back edge
            elif child not in finished:  # Check if the child has not been finished
                stack.append((child, iter(graph[child])))
        except StopIteration:
            stack.pop()  # Done with this node's children
            finished.add(node)  # Mark this node as finished


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
    queue = [source]
    traversed = set()

    frontier = set(frontier)

    while queue:
        node = queue.pop(0)
        traversed.add(node)

        for _, succ, data in graph.out_edges(node, data=True):
            if g0.has_edge(node, succ):
                continue

            g0.add_edge(node, succ, **data)
            if succ in traversed or succ in frontier:
                continue
            for frontier_node in frontier:
                if networkx.has_path(graph, succ, frontier_node):
                    queue.append(succ)
                    break

    # recursively remove all nodes that have less than two neighbors
    to_remove = [
        n
        for n in g0.nodes()
        if n not in frontier and n is not source and (g0.out_degree[n] == 0 or g0.in_degree[n] == 0)
    ]
    while to_remove:
        g0.remove_nodes_from(to_remove)
        to_remove = [
            n
            for n in g0.nodes()
            if n not in frontier and n is not source and (g0.out_degree[n] == 0 or g0.in_degree[n] == 0)
        ]

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

    __slots__ = ["_label"]

    def __init__(self, label):
        self._label = label

    def __repr__(self):
        return "TN[%s]" % self._label

    def __eq__(self, other):
        if isinstance(other, TemporaryNode) and other._label == self._label:
            return True
        return False

    def __hash__(self):
        return hash(("TemporaryNode", self._label))


class ContainerNode:
    """
    A container node.

    Only used in dominator tree generation. We did this so we can set the index property without modifying the
    original object.
    """

    __slots__ = ["_obj", "index"]

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
        return hash(("CN", self._obj))

    def __repr__(self):
        return "CN[%s]" % repr(self._obj)


class Dominators:
    """
    Describes dominators in a graph.
    """

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
                if node in scanned_nodes:
                    continue
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

            if counter >= all_nodes_count:
                break

            self._l.debug(
                "%d nodes are left out during the DFS. They must formed a cycle themselves.", all_nodes_count - counter
            )
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
            if (
                self._semi[self._label[self._ancestor[v.index].index].index].index
                < self._semi[self._label[v.index].index].index
            ):
                self._label[v.index] = self._label[self._ancestor[v.index].index]
            self._ancestor[v.index] = self._ancestor[self._ancestor[v.index].index]


class PostDominators(Dominators):
    """
    Describe post-dominators in a graph.
    """

    def __init__(self, graph, entry_node, successors_func=None):
        super().__init__(graph, entry_node, successors_func=successors_func, reverse=True)

    @property
    def post_dom(self) -> networkx.DiGraph:
        return self.dom


class SCCPlaceholder:
    """
    Describes a placeholder for strongly-connected-components in a graph.
    """

    __slots__ = ("scc_id",)

    def __init__(self, scc_id):
        self.scc_id = scc_id

    def __eq__(self, other):
        return isinstance(other, SCCPlaceholder) and other.scc_id == self.scc_id

    def __hash__(self):
        return hash("scc_placeholder_%d" % self.scc_id)


class GraphUtils:
    """
    A helper class with some static methods and algorithms implemented, that in fact, might take more than just normal
    CFGs.
    """

    @staticmethod
    def find_merge_points(function_addr, function_endpoints, graph):  # pylint:disable=unused-argument
        """
        Given a local transition graph of a function, find all merge points inside, and then perform a
        quasi-topological sort of those merge points.

        A merge point might be one of the following cases:
        - two or more paths come together, and ends at the same address.
        - end of the current function

        :param int function_addr: Address of the function.
        :param list function_endpoints: Endpoints of the function. They typically come from Function.endpoints.
        :param networkx.DiGraph graph: A local transition graph of a function. Normally it comes from Function.graph.
        :return: A list of ordered addresses of merge points.
        :rtype: list
        """

        merge_points = set()

        for node in graph.nodes():
            if graph.in_degree(node) > 1:
                merge_points.add(node)

        ordered_merge_points = GraphUtils.quasi_topological_sort_nodes(graph, merge_points)

        addrs = [n.addr for n in ordered_merge_points]
        return addrs

    @staticmethod
    def find_widening_points(function_addr, function_endpoints, graph):  # pylint: disable=unused-argument
        """
        Given a local transition graph of a function, find all widening points inside.

        Correctly choosing widening points is very important in order to not lose too much information during static
        analysis. We mainly consider merge points that has at least one loop back edges coming in as widening points.

        :param int function_addr: Address of the function.
        :param list function_endpoints: Endpoints of the function, typically coming from Function.endpoints.
        :param networkx.DiGraph graph: A local transition graph of a function, normally Function.graph.
        :return: A list of addresses of widening points.
        :rtype: list
        """

        sccs = networkx.strongly_connected_components(graph)

        widening_addrs = set()

        for scc in sccs:
            if len(scc) == 1:
                node = next(iter(scc))
                if graph.has_edge(node, node):
                    # self loop
                    widening_addrs.add(node.addr)
            else:
                for n in scc:
                    predecessors = graph.predecessors(n)
                    if any(p not in scc for p in predecessors):
                        widening_addrs.add(n.addr)
                        break

        return list(widening_addrs)

    @staticmethod
    def reverse_post_order_sort_nodes(graph, nodes=None):
        """
        Sort a given set of nodes in reverse post ordering.

        :param networkx.DiGraph graph: A local transition graph of a function.
        :param iterable nodes: A collection of nodes to sort.
        :return: A list of sorted nodes.
        :rtype: list
        """

        post_order = networkx.dfs_postorder_nodes(graph)

        if nodes is None:
            return reversed(list(post_order))

        addrs_to_index = {n.addr: i for (i, n) in enumerate(post_order)}
        return sorted(nodes, key=lambda n: addrs_to_index[n.addr], reverse=True)

    @staticmethod
    def quasi_topological_sort_nodes(
        graph: networkx.DiGraph, nodes: list | None = None, loop_heads: list | None = None
    ) -> list:
        """
        Sort a given set of nodes from a graph based on the following rules:

        # - if A -> B and not B -> A, then we have A < B
        # - if A -> B and B -> A, then the ordering is undefined

        Following the above rules gives us a quasi-topological sorting of nodes in the graph. It also works for cyclic
        graphs.

        :param graph:       A local transition graph of the function.
        :param nodes:       A list of nodes to sort. None if you want to sort all nodes inside the graph.
        :param loop_heads:  A list of nodes that should be treated loop heads.
        :return:            A list of ordered nodes.
        """

        # fast path for single node graphs
        if graph.number_of_nodes() == 1:
            if nodes is None:
                return list(graph.nodes)
            return [n for n in graph.nodes() if n in nodes]

        # make a copy to the graph since we are gonna modify it
        graph_copy = networkx.DiGraph()

        # find all strongly connected components in the graph
        sccs = [scc for scc in networkx.strongly_connected_components(graph) if len(scc) > 1]

        def _sort_edge(edge):
            """
            A sorter to make a deterministic order of edges.
            """
            _src, _dst = edge
            src_addr, dst_addr = 0, 0
            if hasattr(_src, "addr"):
                src_addr = _src.addr
            elif isinstance(_src, int):
                src_addr = _src

            if hasattr(_dst, "addr"):
                dst_addr = _dst.addr
            elif isinstance(_dst, int):
                dst_addr = _dst

            return src_addr + dst_addr

        # collapse all strongly connected components
        edges = sorted(list(graph.edges()), key=_sort_edge)
        for src, dst in edges:
            scc_index = GraphUtils._components_index_node(sccs, src)
            if scc_index is not None:
                src = SCCPlaceholder(scc_index)
            scc_index = GraphUtils._components_index_node(sccs, dst)
            if scc_index is not None:
                dst = SCCPlaceholder(scc_index)

            if isinstance(src, SCCPlaceholder) and isinstance(dst, SCCPlaceholder) and src == dst:
                if src not in graph_copy:
                    graph_copy.add_node(src)
                continue
            if src == dst:
                if src not in graph_copy:
                    graph_copy.add_node(src)
                continue

            graph_copy.add_edge(src, dst)

        # add loners
        out_degree_zero_nodes = [node for (node, degree) in graph.out_degree() if degree == 0]
        for node in out_degree_zero_nodes:
            if graph.in_degree(node) == 0:
                graph_copy.add_node(node)

        # topological sort on acyclic graph `graph_copy`
        tmp_nodes = networkx.topological_sort(graph_copy)

        ordered_nodes = []
        for n in tmp_nodes:
            if isinstance(n, SCCPlaceholder):
                GraphUtils._append_scc(graph, ordered_nodes, sccs[n.scc_id], loop_head_candidates=loop_heads)
            else:
                ordered_nodes.append(n)

        if nodes is None:
            return ordered_nodes

        nodes = set(nodes)
        ordered_nodes = [n for n in ordered_nodes if n in nodes]
        return ordered_nodes

    @staticmethod
    def _components_index_node(components, node):
        for i, comp in enumerate(components):
            if node in comp:
                return i
        return None

    @staticmethod
    def _append_scc(
        graph: networkx.DiGraph, ordered_nodes: list, scc: set, loop_head_candidates: list | None = None
    ) -> None:
        """
        Append all nodes from a strongly connected component to a list of ordered nodes and ensure the topological
        order.

        :param graph: The graph where all nodes belong to.
        :param ordered_nodes:     Ordered nodes.
        :param scc:           A set of nodes that forms a strongly connected component in the graph.
        """

        loop_head = None

        if loop_head_candidates is not None:
            # find the first node that appears in loop_heads
            loop_head_candidates = set(loop_head_candidates)
            for n in scc:
                if n in loop_head_candidates:
                    loop_head = n
                    break

        if loop_head is None:
            for parent_node in reversed(ordered_nodes):
                # find all successors to this node
                succs = set(graph.successors(parent_node))
                scc_succs = scc.intersection(succs)
                if len(scc_succs) == 1:
                    loop_head = next(iter(scc_succs))
                    break
                if len(scc_succs) > 1:
                    # calculate the distance between each pair of nodes within scc_succs, pick the one with the
                    # shortest total distance
                    scc_node_distance = defaultdict(int)
                    for scc_succ in scc_succs:
                        for other_node in scc_succs:
                            if other_node is scc_succ:
                                continue
                            scc_node_distance[scc_succ] += networkx.algorithms.shortest_path_length(
                                graph, scc_succ, other_node
                            )
                    distance_to_node = {v: k for k, v in scc_node_distance.items()}
                    lowest_distance = min(distance_to_node)
                    loop_head = distance_to_node[lowest_distance]
                    break

        if loop_head is None:
            # randomly pick one
            loop_head = next(iter(scc))

        subgraph: networkx.DiGraph = graph.subgraph(scc).copy()
        for src, _ in list(subgraph.in_edges(loop_head)):
            subgraph.remove_edge(src, loop_head)

        # panic mode: if the strongly connected component has too many edges (imagine an almost complete graph), it
        # will take too long to converge if we only remove one node out of the component each time. we introduce a
        # panic mode that will aggressively remove edges

        if len(subgraph) > 3000 and len(subgraph.edges) > len(subgraph) * 1.4:
            for n in scc:
                if subgraph.in_degree[n] >= 1 and subgraph.out_degree[n] >= 1:
                    for src in list(subgraph.predecessors(n)):
                        if src is not n:
                            subgraph.remove_edge(src, n)
                            if len(subgraph.edges) <= len(subgraph) * 1.4:
                                break

        ordered_nodes.extend(GraphUtils.quasi_topological_sort_nodes(subgraph))
