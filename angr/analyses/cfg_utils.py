
from collections import defaultdict

import networkx


class SCCPlaceholder(object):
    def __init__(self, scc_id):
        self.scc_id = scc_id

    def __eq__(self, other):
        return isinstance(other, SCCPlaceholder) and other.scc_id == self.scc_id

    def __hash__(self):
        return hash('scc_placeholder_%d' % self.scc_id)


class CFGUtils(object):
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

        in_degree_to_nodes = defaultdict(set)

        for node in graph.nodes_iter():
            in_degree = graph.in_degree(node)
            in_degree_to_nodes[in_degree].add(node)
            if in_degree > 1:
                merge_points.add(node)

        ordered_merge_points = CFGUtils.quasi_topological_sort_nodes(graph, merge_points)

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
                    if any([ p not in scc for p in predecessors]):
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
        else:
            addrs_to_index = {}
            for i, n in enumerate(post_order):
                addrs_to_index[n.addr] = i
            return sorted(nodes, key=lambda n: addrs_to_index[n.addr], reverse=True)

    @staticmethod
    def quasi_topological_sort_nodes(graph, nodes=None):
        """
        Sort a given set of nodes from a graph based on the following rules:

        # - if A -> B and not B -> A, then we have A < B
        # - if A -> B and B -> A, then the ordering is undefined

        Following the above rules gives us a quasi-topological sorting of nodes in the graph. It also works for cyclic
        graphs.

        :param networkx.DiGraph graph: A local transition graph of the function.
        :param iterable nodes: A list of nodes to sort. None if you want to sort all nodes inside the graph.
        :return: A list of ordered nodes.
        :rtype: list
        """

        # make a copy to the graph since we are gonna modify it
        graph_copy = networkx.DiGraph()

        # find all strongly connected components in the graph
        sccs = [ scc for scc in networkx.strongly_connected_components(graph) if len(scc) > 1 ]

        # collapse all strongly connected components
        for src, dst in graph.edges_iter():
            scc_index = CFGUtils._components_index_node(sccs, src)
            if scc_index is not None:
                src = SCCPlaceholder(scc_index)
            scc_index = CFGUtils._components_index_node(sccs, dst)
            if scc_index is not None:
                dst = SCCPlaceholder(scc_index)

            if isinstance(src, SCCPlaceholder) and isinstance(dst, SCCPlaceholder) and src == dst:
                continue
            if src == dst:
                continue

            graph_copy.add_edge(src, dst)

        # topological sort on acyclic graph `graph_copy`
        tmp_nodes = networkx.topological_sort(graph_copy)

        ordered_nodes = [ ]
        for n in tmp_nodes:
            if isinstance(n, SCCPlaceholder):
                ordered_nodes += list(sccs[n.scc_id])
            else:
                ordered_nodes.append(n)

        if nodes is None:
            return ordered_nodes
        else:
            nodes = set(nodes)
            ordered_nodes = [ n for n in ordered_nodes if n in nodes ]
            return ordered_nodes

    @staticmethod
    def _components_index_node(components, node):

        for i, comp in enumerate(components):
            if node in comp:
                return i
        return None
