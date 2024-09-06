from __future__ import annotations
from typing import Any

import networkx

from ..utils import structured_node_is_simple_return
from ....utils.graph import PostDominators, TemporaryNode
from .phoenix import PhoenixStructurer


class SAILRStructurer(PhoenixStructurer):
    """
    The SAILR structuring algorithm is the phoenix-based algorithm from the USENIX 2024 paper SAILR.
    The entirety of the algorithm is implemented across this class and various optimization passes in the decompiler.
    To find each optimization class, simply search for optimizations which reference this class.NAME.

    At a high-level, SAILR does three things different from the traditional Phoenix schema-based algorithm:
    1. It recursively structures the graph, rather than doing it in a single pass. This allows decisions to be made
        based on the current state of what the decompilation would look like.
    2. It performs deoptimizations targeting specific optimizations that introduces gotos and mis-structured code.
        It can only do this because of the recursive nature of the algorithm.
    3. It uses a more advanced heuristic for virtualizing edges, which is implemented in this class.

    Additionally, some changes in Phoenix are only activated when SAILR is used.
    """

    NAME = "sailr"

    def __init__(self, region, improve_phoenix=True, **kwargs):
        super().__init__(
            region,
            improve_algorithm=improve_phoenix,
            **kwargs,
        )

    def _order_virtualizable_edges(self, graph: networkx.DiGraph, edges: list, node_seq: dict[Any, int]) -> list:
        """
        The criteria for "best" is defined by a variety of heuristics described below.
        """
        if len(edges) <= 1:
            return edges

        # TODO: the graph we have here is not an accurate graph and can have no "entry node". We need a better graph.
        try:
            entry_node = next(node for node in graph.nodes if graph.in_degree(node) == 0)
        except StopIteration:
            entry_node = None

        best_edges = edges
        if entry_node is not None:
            # the first few heuristics are based on the post-dominator count of the edge
            # so we collect them for each candidate edge
            edge_postdom_count = {}
            edge_sibling_count = {}
            for edge in edges:
                _, dst = edge
                graph_copy = networkx.DiGraph(graph)
                graph_copy.remove_edge(*edge)
                sibling_cnt = graph_copy.in_degree(dst)
                if sibling_cnt == 0:
                    continue

                edge_sibling_count[edge] = sibling_cnt
                post_dom_graph = PostDominators(graph_copy, entry_node).post_dom
                post_doms = set()
                for postdom_node, dominatee in post_dom_graph.edges():
                    if not isinstance(postdom_node, TemporaryNode) and not isinstance(dominatee, TemporaryNode):
                        post_doms.add((postdom_node, dominatee))
                edge_postdom_count[edge] = len(post_doms)

                # H1: the edge that has the least amount of sibling edges should be virtualized first
                # this is believed to reduce the amount of virtualization needed in future rounds and increase
                # the edges that enter a single outer-scope if-stmt
                if edge_sibling_count:
                    min_sibling_count = min(edge_sibling_count.values())
                    best_edges = [edge for edge, cnt in edge_sibling_count.items() if cnt == min_sibling_count]
                    if len(best_edges) == 1:
                        return best_edges

                    # create the next heuristic based on the best edges from the previous heuristic
                    filtered_edge_postdom_count = edge_postdom_count.copy()
                    for edge in list(edge_postdom_count.keys()):
                        if edge not in best_edges:
                            del filtered_edge_postdom_count[edge]
                    if filtered_edge_postdom_count:
                        edge_postdom_count = filtered_edge_postdom_count

                # H2: the edge, when removed, that causes the most post-dominators of the graph should be virtualized
                # first. this is believed to make the code more linear looking be reducing the amount of scopes.
                # informally, we believe post-dominators to be an inverse indicator of the number of scopes present
                if edge_postdom_count:
                    max_postdom_count = max(edge_postdom_count.values())
                    best_edges = [edge for edge, cnt in edge_postdom_count.items() if cnt == max_postdom_count]
                    if len(best_edges) == 1:
                        return best_edges

                # H3: the edge that goes directly to a return statement should be virtualized first
                # this is believed to be good because it can be corrected in later optimization by duplicating
                # the return
                candidate_edges = best_edges
                best_edges = []
                for src, dst in candidate_edges:
                    if graph.has_node(dst) and structured_node_is_simple_return(dst, graph):
                        best_edges.append((src, dst))

                if len(best_edges) == 1:
                    return best_edges
                if not best_edges:
                    best_edges = candidate_edges

        # if we have another tie, or we never used improved heuristics, then we do the default ordering.
        return super()._order_virtualizable_edges(graph, best_edges, node_seq)
