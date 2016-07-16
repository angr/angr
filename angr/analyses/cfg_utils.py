
from collections import defaultdict

import networkx

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
                merge_points.add(node.addr)

        # Revised version of a topological sort
        # we define a partial order between two merge points as follows:
        # - if A -> B and not B -> A, then we have A < B
        # - if A -> B and B -> A, and in a BFS, A is visited before B, then we have A < B
        # - if A -> B and B -> A, and none of them were visited before, and addr(A) < addr(B), then we have A < B

        ordered_merge_points = CFGUtils.quasi_topological_sort_nodes(graph,
                                                                     node_addrs=merge_points,
                                                                     in_degree_to_nodes=in_degree_to_nodes
                                                                     )

        addrs = [n.addr for n in ordered_merge_points]
        return addrs

    @staticmethod
    def quasi_topological_sort_nodes(graph, node_addrs=None, in_degree_to_nodes=None):
        """
        Sort a given set of nodes based on the following rules:

        # - if A -> B and not B -> A, then we have A < B
        # - if A -> B and B -> A, and in a BFS, A is visited before B, then we have A < B
        # - if A -> B and B -> A, and none of them were visited before, and addr(A) < addr(B), then we have A < B

        The above rules can be viewed as a quasi-topological sorting of nodes in the graph.

        :param networkx.DiGraph graph: A local transition graph of the function.
        :param list node_addrs: A list of node addresses to sort. None if you want to sort all nodes inside the graph.
        :param dict in_degree_to_nodes: A mapping between in-degrees and sets of nodes.
        :return: A list of ordered nodes.
        :rtype: list
        """

        # make a copy to the graph since we are gonna modify it
        graph_copy = networkx.DiGraph(graph)

        # store nodes that are visited and whose in-degree is not 0
        waiting_queue = []

        ordered_nodes = []

        if in_degree_to_nodes is None:
            # initialize in_degree_to_nodes mapping
            in_degree_to_nodes = defaultdict(set)
            for node in graph.nodes_iter():
                in_degree = graph.in_degree(node)
                in_degree_to_nodes[in_degree].add(node)

        while graph_copy.number_of_nodes():
            if not in_degree_to_nodes[0]:
                # there is a loop somewhere

                # get a node out of the waiting queue
                n = waiting_queue[0]
                waiting_queue = waiting_queue[1:]

                # get all edges that has `n` as the destination
                in_edges = graph_copy.in_edges(n)
                # get all successors of n
                successors = [ suc for suc in graph_copy.successors(n) if suc is not n ]
                # since there are loops, we want to create new edges from those old destination to all successors of n,
                # in order to keep the topology right
                for src, _ in in_edges:
                    for suc in successors:
                        if src is not suc:
                            in_degree = graph_copy.in_degree(suc)
                            if suc not in graph_copy[src]:
                                graph_copy.add_edge(src, suc)
                                in_degree_to_nodes[in_degree].remove(suc)
                                in_degree_to_nodes[in_degree + 1].add(suc)

                # remove all edges that has `n` as the destination
                for src, _ in in_edges:
                    graph_copy.remove_edge(src, n)

            else:
                # get an zero-in-degree node
                n = in_degree_to_nodes[0].pop()

            if node_addrs is None or n.addr in node_addrs:
                ordered_nodes.append(n)

            if n in waiting_queue:
                waiting_queue.remove(n)

            if n not in graph_copy:
                continue

            out_edges = graph_copy.out_edges(n)

            # now remove all out_edges
            for edge in out_edges:
                _, dst = edge
                if n is not dst:
                    in_degree = graph_copy.in_degree(dst)
                    in_degree_to_nodes[in_degree].remove(dst)
                    in_degree_to_nodes[in_degree - 1].add(dst)

                graph_copy.remove_edge(n, dst)

                if dst not in waiting_queue:
                    waiting_queue.append(dst)

            graph_copy.remove_node(n)

        return ordered_nodes
