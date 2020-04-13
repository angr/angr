
from itertools import count
import logging

import networkx

from ... import AnalysesHub
from .optimization_pass import OptimizationPass


_l = logging.getLogger(name=__name__)


class EagerReturnsSimplifier(OptimizationPass):
    """
    Some compilers (if not all) generate only one returning block for a function regardless of how many returns there
    are in the source code. This oftentimes result in irreducible graphs and reduce the readability of the decompiled
    code. This optimization pass will make the function return eagerly by duplicating the return site of a function
    multiple times and assigning one copy of the return site to each of its sources when certain thresholds are met.

    Note that this simplifier may reduce the readability of the generated code in certain cases, especially if the graph
    is already reducible without applying this simplifier.

    :ivar int max_level:    Number of times that we repeat the process of making returns eager.
    :ivar int min_indegree: The minimum in-degree of the return site to be duplicated.
    :ivar node_idx:         The next node index. Each duplicated return site gets assigned a unique index, otherwise
                            those duplicates will be considered as the same block in the graph because they have the
                            same hash.
    """

    # TODO: This optimization pass may support more architectures and platforms
    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["linux"]

    def __init__(self, func, blocks, graph,
                 # internal parameters that should be used by Clinic
                 node_idx_start=0,
                 # settings
                 max_level=2,
                 min_indegree=4):

        super().__init__(func, blocks=blocks, graph=graph)

        self.max_level = max_level
        self.min_indegree = min_indegree
        self.node_idx = count(start=node_idx_start)

        self.analyze()

    def _check(self):

        # does this function return?
        if self._func.returning is False:
            return False, None

        # TODO: More filtering

        return True, None

    def _analyze(self, cache=None):

        # for each block with no successors and more than 1 predecessors, make copies of this block and link it back to
        # the sources of incoming edges
        graph_copy = networkx.DiGraph(self._graph)
        graph_updated = False

        # attempt at most N levels
        for _ in range(self.max_level):
            r = self._analyze_core(graph_copy)
            if not r:
                break
            graph_updated = True

        # the output graph
        if graph_updated:
            self.out_graph = graph_copy

    def _analyze_core(self, graph):

        endnodes = [ node for node in graph.nodes() if graph.out_degree[node] == 0 ]
        graph_changed = False

        for end_node in endnodes:
            in_edges = list(graph.in_edges(end_node))

            if len(in_edges) > 1:
                region = [ end_node ]
            elif len(in_edges) == 1:
                # back-trace until it reaches a node with two predecessors
                region = self._single_entry_region(graph, end_node)
                in_edges = list(graph.in_edges(region[0]))
            else:  # len(in_edges) == 0
                continue

            # region and in_edge might have been updated. re-check
            if not in_edges:
                # this is a single connected component in the graph
                # no need to duplicate anything
                continue
            if len(in_edges) == 1:
                # there is no need to duplicate it
                continue
            if len(in_edges) < self.min_indegree:
                # does not meet the threshold
                continue

            # update the graph
            for in_edge in in_edges:
                pred_node = in_edge[0]
                # Modify the graph and then add an edge to the copy of the region
                region_copy = [ node.copy() for node in region ]
                for node in region_copy:
                    node.idx = next(self.node_idx)

                graph.add_edge(pred_node, region_copy[0])
                for node_a, node_b in zip(region_copy[:-1], region_copy[1:]):
                    graph.add_edge(node_a, node_b)

            # remove all in-edges
            graph.remove_edges_from(in_edges)
            # remove the node to be copied
            graph.remove_nodes_from(region)
            graph_changed = True

        return graph_changed

    @staticmethod
    def _single_entry_region(graph, end_node):
        """
        Back track on the graph from `end_node` and find the longest chain of nodes where each node has only one
        predecessor and one successor.

        :param end_node:    A node in the graph.
        :return:            A list of nodes where the first node either has no predecessors or at least two
                            predecessors.
        :rtype:             list
        """

        region = [ end_node ]
        traversed = { end_node }
        node = end_node
        while True:
            preds = list(graph.predecessors(node))
            if len(preds) != 1:
                break
            node = preds[0]
            if graph.out_degree[node] != 1:
                break
            if node in traversed:
                break
            region.insert(0, node)
            traversed.add(node)
        return region


AnalysesHub.register_default("EagerReturnsSimplifier", EagerReturnsSimplifier)
