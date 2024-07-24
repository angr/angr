from __future__ import annotations
from itertools import count
from collections import defaultdict
import logging

import networkx

import ailment
from ailment import Block
from ailment.statement import ConditionalJump, Jump
from ailment.expression import Const

from angr.utils.graph import GraphUtils
from ...utils.graph import dfs_back_edges, subgraph_between_nodes, dominates, shallow_reverse
from ...errors import AngrRuntimeError
from .. import Analysis, register_analysis
from .structuring.structurer_nodes import MultiNode, ConditionNode, IncompleteSwitchCaseHeadStatement
from .graph_region import GraphRegion
from .condition_processor import ConditionProcessor
from .utils import replace_last_statement, first_nonlabel_nonphi_statement, copy_graph

l = logging.getLogger(name=__name__)


# an ever-incrementing counter
CONDITIONNODE_ADDR = count(0xFF000000)


class RegionIdentifier(Analysis):
    """
    Identifies regions within a function graph and creates a recursive GraphRegion object.
    Note, that the analysis may modify the graph in-place. If you want to keep the original graph,
    set the `update_graph` parameter to False.
    """

    def __init__(
        self,
        func,
        cond_proc=None,
        graph=None,
        update_graph=True,
        largest_successor_tree_outside_loop=True,
        force_loop_single_exit=True,
        complete_successors=False,
    ):
        self.function = func
        self.cond_proc = (
            cond_proc
            if cond_proc is not None
            else ConditionProcessor(
                self.project.arch
                if getattr(self, "project", None) is not None
                else None  # it's only None in test cases
            )
        )
        self._graph = graph if graph is not None else self.function.graph
        if not update_graph:
            # copy the graph so updates don't affect the original graph
            self._graph = copy_graph(self._graph)

        self.region = None
        self._start_node = None
        self._loop_headers: list | None = None
        self.regions_by_block_addrs = []
        self._largest_successor_tree_outside_loop = largest_successor_tree_outside_loop
        self._force_loop_single_exit = force_loop_single_exit
        self._complete_successors = complete_successors

        self._analyze()

    @staticmethod
    def slice_graph(graph, node, frontier, include_frontier=False):
        """
        Generate a slice of the graph from the head node to the given frontier.

        :param networkx.DiGraph graph: The graph to work on.
        :param node: The starting node in the graph.
        :param frontier: A list of frontier nodes.
        :param bool include_frontier: Whether the frontier nodes are included in the slice or not.
        :return: A subgraph.
        :rtype: networkx.DiGraph
        """

        subgraph = subgraph_between_nodes(graph, node, frontier, include_frontier=include_frontier)
        # HACK: FIXME: for infinite loop nodes, this would return an empty set, so we include the loop body itself
        # Make sure this makes sense (EDG thinks it does)
        if not list(subgraph.nodes) and (node, node) in graph.edges:
            subgraph.add_edge(node, node)
        return subgraph

    def _analyze(self):
        # make a copy of the graph
        graph = networkx.DiGraph(self._graph)

        # preprocess: make it a super graph
        self._make_supergraph(graph)

        self._start_node = self._get_start_node(graph)

        self.region = self._make_regions(graph)

        # make regions into block address lists
        self.regions_by_block_addrs = self._make_regions_by_block_addrs()

    def _make_regions_by_block_addrs(self) -> list[list[int]]:
        """
        Creates a list of addr lists representing each region without recursion. A single region is defined
        as a set of only blocks, no Graphs containing nested regions. The list contains the address of each
        block in the region, including the heads of each recursive region.

        @return: List of addr lists
        """

        work_list = [self.region]
        block_only_regions = []
        seen_regions = set()
        while work_list:
            children_regions = []
            for region in work_list:
                children_blocks = []
                for node in region.graph.nodes:
                    if isinstance(node, Block):
                        children_blocks.append(node.addr)
                    elif isinstance(node, MultiNode):
                        children_blocks += [n.addr for n in node.nodes]
                    elif isinstance(node, GraphRegion):
                        if node not in seen_regions:
                            children_regions.append(node)
                            children_blocks.append(node.head.addr)
                            seen_regions.add(node)
                    else:
                        continue

                if children_blocks:
                    block_only_regions.append(children_blocks)

            work_list = children_regions

        return block_only_regions

    def _get_start_node(self, graph: networkx.DiGraph):
        try:
            return next(n for n in graph.nodes() if graph.in_degree(n) == 0)
        except StopIteration:
            pass

        try:
            return next(n for n in graph.nodes() if n.addr == self.function.addr)
        except StopIteration as ex:
            raise AngrRuntimeError("Cannot find the start node from the graph!") from ex

    def _test_reducibility(self):
        # make a copy of the graph
        graph = networkx.DiGraph(self._graph)

        # preprocess: make it a super graph
        self._make_supergraph(graph)

        while True:
            changed = False

            # find a node with a back-edge, remove the edge (deleting the loop), and replace it with a MultiNode
            changed |= self._remove_self_loop(graph)

            # find a node that has only one predecessor, and merge it with its predecessor (replace them with a
            # MultiNode)
            changed |= self._merge_single_entry_node(graph)

            if not changed:
                # a fixed-point is reached
                break

        # Flow graph reducibility, Hecht and Ullman
        return len(graph.nodes) == 1

    def _make_supergraph(self, graph: networkx.DiGraph):
        while True:
            for src, dst, data in graph.edges(data=True):
                type_ = data.get("type", None)
                if type_ == "fake_return":
                    if len(list(graph.successors(src))) == 1 and len(list(graph.predecessors(dst))) == 1:
                        self._merge_nodes(graph, src, dst, force_multinode=True)
                        break
                elif type_ == "call":
                    graph.remove_node(dst)
                    break
            else:
                break

    def _find_loop_headers(self, graph: networkx.DiGraph) -> list:
        heads = {t for _, t in dfs_back_edges(graph, self._start_node)}
        return GraphUtils.quasi_topological_sort_nodes(graph, heads)

    def _find_initial_loop_nodes(self, graph: networkx.DiGraph, head):
        # TODO optimize
        latching_nodes = {s for s, t in dfs_back_edges(graph, self._start_node) if t == head}
        loop_subgraph = self.slice_graph(graph, head, latching_nodes, include_frontier=True)

        # special case: any node with more than two non-self successors are probably the head of a switch-case. we
        # should include all successors into the loop subgraph.
        while True:
            updated = False
            for node in list(loop_subgraph):
                nonself_successors = [succ for succ in graph.successors(node) if succ is not node]
                if len(nonself_successors) > 2:
                    for succ in nonself_successors:
                        if not loop_subgraph.has_edge(node, succ):
                            updated = True
                            loop_subgraph.add_edge(node, succ)
            if not updated:
                break

        return set(loop_subgraph)

    def _refine_loop(self, graph: networkx.DiGraph, head, initial_loop_nodes, initial_exit_nodes):
        if len(initial_exit_nodes) <= 1:
            return initial_loop_nodes, initial_exit_nodes

        refined_loop_nodes = initial_loop_nodes.copy()
        refined_exit_nodes = initial_exit_nodes.copy()

        # simple optimization: include all single-in-degree successors of existing loop nodes
        while True:
            added = set()
            for exit_node in list(refined_exit_nodes):
                if graph.in_degree[exit_node] == 1 and graph.out_degree[exit_node] <= 1:
                    added.add(exit_node)
                    refined_loop_nodes.add(exit_node)
                    refined_exit_nodes |= {
                        succ for succ in graph.successors(exit_node) if succ not in refined_loop_nodes
                    }
                    refined_exit_nodes.remove(exit_node)
            if not added:
                break

        if len(refined_exit_nodes) <= 1:
            return refined_loop_nodes, refined_exit_nodes

        idom = networkx.immediate_dominators(graph, head)

        new_exit_nodes = refined_exit_nodes
        # a graph with only initial exit nodes and new loop nodes that are reachable from at least one initial exit
        # node.
        subgraph = networkx.DiGraph()

        sorted_refined_exit_nodes = GraphUtils.quasi_topological_sort_nodes(graph, refined_exit_nodes)
        while len(sorted_refined_exit_nodes) > 1 and new_exit_nodes:
            # visit each node in refined_exit_nodes once and determine which nodes to consider as loop nodes
            candidate_nodes = {}
            for n in list(sorted_refined_exit_nodes):
                if all((pred is n or pred in refined_loop_nodes) for pred in graph.predecessors(n)) and dominates(
                    idom, head, n
                ):
                    to_add = set(graph.successors(n)) - refined_loop_nodes
                    candidate_nodes[n] = to_add

            # visit all candidate nodes and only consider candidates that will not be added as exit nodes
            all_new_exit_candidates = set()
            for new_exit_candidates in candidate_nodes.values():
                all_new_exit_candidates |= new_exit_candidates

            # to guarantee progressing, we must ensure all_new_exit_candidates cannot contain all candidate nodes
            if all(n in all_new_exit_candidates for n in candidate_nodes):
                all_new_exit_candidates = set()

            # do the actual work
            new_exit_nodes = set()
            for n in candidate_nodes:
                if n in all_new_exit_candidates:
                    continue
                refined_loop_nodes.add(n)
                sorted_refined_exit_nodes.remove(n)
                to_add = set(graph.successors(n)) - refined_loop_nodes
                new_exit_nodes |= to_add
                for succ in to_add:
                    subgraph.add_edge(n, succ)

            sorted_refined_exit_nodes += list(new_exit_nodes)
            sorted_refined_exit_nodes = list(set(sorted_refined_exit_nodes))
            sorted_refined_exit_nodes = GraphUtils.quasi_topological_sort_nodes(graph, sorted_refined_exit_nodes)

        refined_exit_nodes = set(sorted_refined_exit_nodes)
        refined_loop_nodes = refined_loop_nodes - refined_exit_nodes

        if self._largest_successor_tree_outside_loop and not refined_exit_nodes:
            # figure out the new successor tree with the highest number of nodes
            initial_exit_to_newnodes = defaultdict(set)
            newnode_to_initial_exits = defaultdict(set)
            for initial_exit in initial_exit_nodes:
                if initial_exit in subgraph:
                    for _, succs in networkx.bfs_successors(subgraph, initial_exit):
                        initial_exit_to_newnodes[initial_exit] |= set(succs)
                        for succ in succs:
                            newnode_to_initial_exits[succ].add(initial_exit)

            for newnode, exits in newnode_to_initial_exits.items():
                for exit_ in exits:
                    initial_exit_to_newnodes[exit_].add(newnode)

            # filter initial_exit_to_newnodes and remove the subtrees with nodes that are reachable from nodes that are
            # outside the current subtree
            for initial_exit, subtree in list(initial_exit_to_newnodes.items()):
                subtree_preds = set()
                for node in subtree:
                    preds = set(graph.predecessors(node))
                    subtree_preds |= {pred for pred in preds if pred not in subtree}
                    if len(subtree_preds) > 1:
                        # early break
                        break

                if len(subtree_preds) > 1:
                    # there is more than one out-of-tree predecessor. remove this subtree
                    del initial_exit_to_newnodes[initial_exit]

            if initial_exit_to_newnodes:
                tree_sizes = {exit_: len(initial_exit_to_newnodes[exit_]) for exit_ in initial_exit_to_newnodes}
                max_tree_size = max(tree_sizes.values())
                if list(tree_sizes.values()).count(max_tree_size) == 1:
                    tree_size_to_exit = {v: k for k, v in tree_sizes.items()}
                    max_size_exit = tree_size_to_exit[max_tree_size]
                    if all(len(newnode_to_initial_exits[nn]) == 1 for nn in initial_exit_to_newnodes[max_size_exit]):
                        refined_loop_nodes = (
                            refined_loop_nodes - initial_exit_to_newnodes[max_size_exit] - {max_size_exit}
                        )
                        refined_exit_nodes.add(max_size_exit)

        return refined_loop_nodes, refined_exit_nodes

    def _remove_self_loop(self, graph: networkx.DiGraph):
        r = False

        while True:
            for node in graph.nodes():
                if node in graph[node]:
                    # found a self loop
                    self._remove_node(graph, node)
                    r = True
                    break
            else:
                break

        return r

    def _merge_single_entry_node(self, graph: networkx.DiGraph):
        r = False

        while True:
            for node in networkx.dfs_postorder_nodes(graph):
                preds = graph.predecessors(node)
                if len(preds) == 1:
                    # merge the two nodes
                    self._absorb_node(graph, preds[0], node)
                    r = True
                    break
            else:
                break

        return r

    def _make_regions(self, graph: networkx.DiGraph):
        structured_loop_headers = set()
        new_regions = []

        # FIXME: _get_start_node() will fail if the graph is just a loop

        # iteratively find and make loop regions
        while True:
            # find loop headers
            self._loop_headers = self._find_loop_headers(graph)
            if not self._loop_headers:
                break

            # Find all loops
            while True:
                restart = False

                self._start_node = self._get_start_node(graph)

                # re-find loop headers
                self._loop_headers = self._find_loop_headers(graph)
                if not self._loop_headers:
                    break

                # Start from loops
                for node in list(reversed(self._loop_headers)):
                    if node in structured_loop_headers:
                        continue
                    if node not in graph:
                        continue
                    region = self._make_cyclic_region(node, graph)
                    if region is None:
                        # failed to struct the loop region - remove the header node from loop headers
                        l.debug(
                            "Failed to structure a loop region starting at %#x. Remove it from loop headers.", node.addr
                        )
                        self._loop_headers.remove(node)
                    else:
                        l.debug("Structured a loop region %r.", region)
                        new_regions.append(region)
                        structured_loop_headers.add(node)
                        restart = True
                        break

                if restart:
                    continue

                break

        new_regions.append(GraphRegion(self._get_start_node(graph), graph, None, None, False, None))

        l.debug("Identified %d loop regions.", len(structured_loop_headers))
        l.debug("No more loops left. Start structuring acyclic regions.")
        # No more loops left. Structure acyclic regions.
        while new_regions:
            region = new_regions.pop(0)
            head = region.head
            subgraph = region.graph

            failed_region_attempts = set()
            while self._make_acyclic_region(
                head, subgraph, region.graph_with_successors, failed_region_attempts, region.cyclic
            ):
                if head not in subgraph:
                    # update head
                    head = next(iter(n for n in subgraph.nodes() if n.addr == head.addr))

            head = next(iter(n for n in subgraph.nodes() if n.addr == head.addr))
            region.head = head

        if len(graph.nodes()) == 1 and isinstance(next(iter(graph.nodes())), GraphRegion):
            return next(iter(graph.nodes()))
        # create a large graph region
        new_head = self._get_start_node(graph)
        return GraphRegion(new_head, graph, None, None, False, None)

    #
    # Cyclic regions
    #

    def _make_cyclic_region(self, head, graph: networkx.DiGraph):
        l.debug("Found cyclic region at %#08x", head.addr)
        initial_loop_nodes = self._find_initial_loop_nodes(graph, head)
        l.debug("Initial loop nodes %s", self._dbg_block_list(initial_loop_nodes))

        # Make sure no other loops are contained in the current loop
        if {n for n in initial_loop_nodes if n.addr != head.addr}.intersection(self._loop_headers):
            return None

        normal_entries = {n for n in graph.predecessors(head) if n not in initial_loop_nodes}
        abnormal_entries = set()
        for n in initial_loop_nodes:
            if n == head:
                continue
            preds = set(graph.predecessors(n))
            abnormal_entries |= preds - initial_loop_nodes
        l.debug("Normal entries %s", self._dbg_block_list(normal_entries))
        l.debug("Abnormal entries %s", self._dbg_block_list(abnormal_entries))

        initial_exit_nodes = set()
        for n in initial_loop_nodes:
            succs = set(graph.successors(n))
            initial_exit_nodes |= succs - initial_loop_nodes

        l.debug("Initial exit nodes %s", self._dbg_block_list(initial_exit_nodes))

        refined_loop_nodes, refined_exit_nodes = self._refine_loop(graph, head, initial_loop_nodes, initial_exit_nodes)
        l.debug("Refined loop nodes %s", self._dbg_block_list(refined_loop_nodes))
        l.debug("Refined exit nodes %s", self._dbg_block_list(refined_exit_nodes))

        # make sure there is a jump statement to the outside at the end of each node going to exit nodes.
        # this jump statement will be rewritten to a break statement during structuring.
        for exit_node in refined_exit_nodes:
            for pred in graph.predecessors(exit_node):
                if pred in refined_loop_nodes:
                    self._ensure_jump_at_loop_exit_ends(pred)

        if len(refined_exit_nodes) > 1:
            # self._get_start_node(graph)
            node_post_order = list(networkx.dfs_postorder_nodes(graph, head))
            sorted_exit_nodes = sorted(refined_exit_nodes, key=node_post_order.index)
            normal_exit_node = sorted_exit_nodes[0]
            abnormal_exit_nodes = set(sorted_exit_nodes[1:])
        else:
            normal_exit_node = next(iter(refined_exit_nodes)) if len(refined_exit_nodes) > 0 else None
            abnormal_exit_nodes = set()

        region = self._abstract_cyclic_region(
            graph, refined_loop_nodes, head, normal_entries, abnormal_entries, normal_exit_node, abnormal_exit_nodes
        )
        if len(region.successors) > 1 and self._force_loop_single_exit:
            # multi-successor region. refinement is required
            self._refine_loop_successors(region, graph)

        return region

    def _refine_loop_successors(self, region, graph: networkx.DiGraph):
        """
        If there are multiple successors of a loop, convert them into conditional gotos. Eventually there should be
        only one loop successor.

        :param GraphRegion region:      The cyclic region to refine.
        :param networkx.DiGraph graph:  The current graph that is being structured.
        :return:                        None
        """
        if len(region.successors) <= 1:
            return

        # recover reaching conditions
        self.cond_proc.recover_reaching_conditions(region, with_successors=True)

        successors = list(region.successors)

        condnode_addr = next(CONDITIONNODE_ADDR)
        # create a new successor
        cond = ConditionNode(
            condnode_addr,
            None,
            self.cond_proc.reaching_conditions[successors[0]],
            successors[0],
            false_node=None,
        )
        for succ in successors[1:]:
            cond = ConditionNode(
                condnode_addr,
                None,
                self.cond_proc.reaching_conditions[succ],
                succ,
                false_node=cond,
            )

        g = region.graph_with_successors

        # modify region in place
        region.successors = {cond}
        for succ in successors:
            for src, _, data in list(g.in_edges(succ, data=True)):
                removed_edges = []
                for src2src, _, data_ in list(g.in_edges(src, data=True)):
                    removed_edges.append((src2src, src, data_))
                    g.remove_edge(src2src, src)
                g.remove_edge(src, succ)

                # TODO: rewrite the conditional jumps in src so that it goes to cond-node instead.

                # modify the last statement of src so that it jumps to cond
                replaced_any_stmt = False
                last_stmts = self.cond_proc.get_last_statements(src)
                for last_stmt in last_stmts:
                    if isinstance(last_stmt, ConditionalJump):
                        if (
                            isinstance(last_stmt.true_target, ailment.Expr.Const)
                            and last_stmt.true_target.value == succ.addr
                        ):
                            new_last_stmt = ConditionalJump(
                                last_stmt.idx,
                                last_stmt.condition,
                                ailment.Expr.Const(None, None, condnode_addr, self.project.arch.bits),
                                last_stmt.false_target,
                                ins_addr=last_stmt.ins_addr,
                            )
                        elif (
                            isinstance(last_stmt.false_target, ailment.Expr.Const)
                            and last_stmt.false_target.value == succ.addr
                        ):
                            new_last_stmt = ConditionalJump(
                                last_stmt.idx,
                                last_stmt.condition,
                                last_stmt.true_target,
                                ailment.Expr.Const(None, None, condnode_addr, self.project.arch.bits),
                                ins_addr=last_stmt.ins_addr,
                            )
                        else:
                            # none of the two branches is jumping out of the loop
                            continue
                    elif isinstance(last_stmt, Jump):
                        if isinstance(last_stmt.target, ailment.Expr.Const):
                            new_last_stmt = Jump(
                                last_stmt.idx,
                                ailment.Expr.Const(None, None, condnode_addr, self.project.arch.bits),
                                ins_addr=last_stmt.ins_addr,
                            )
                        else:
                            # an indirect jump - might be a jump table. ignore it
                            continue
                    else:
                        l.error("Unexpected last_stmt type %s. Ignore.", type(last_stmt))
                        continue
                    replace_last_statement(src, last_stmt, new_last_stmt)
                    replaced_any_stmt = True
                if not replaced_any_stmt:
                    l.warning("No statement was replaced. Is there anything wrong?")
                    # raise Exception()

                # add src back
                for src2src, _, data_ in removed_edges:
                    g.add_edge(src2src, src, **data_)

                g.add_edge(src, cond, **data)

        # modify graph
        graph.add_edge(region, cond)
        for succ in successors:
            edge_data = graph.get_edge_data(region, succ)
            graph.remove_edge(region, succ)
            graph.add_edge(cond, succ, **edge_data)

    #
    # Acyclic regions
    #

    def _make_acyclic_region(self, head, graph: networkx.DiGraph, secondary_graph, failed_region_attempts, cyclic):
        # pre-processing

        # we need to create a copy of the original graph if
        # - there are in edges to the head node, or
        # - there are more than one end nodes

        head_inedges = list(graph.in_edges(head))
        if head_inedges:
            # we need a copy of the graph to remove edges coming into the head
            graph_copy = networkx.DiGraph(graph)
            # remove any in-edge to the head node
            for src, _ in head_inedges:
                graph_copy.remove_edge(src, head)
        else:
            graph_copy = graph

        endnodes = [node for node in graph_copy.nodes() if graph_copy.out_degree(node) == 0]
        if len(endnodes) == 0:
            # sanity check: there should be at least one end node
            l.critical("No end node is found in a supposedly acyclic graph. Is it really acyclic?")
            return False

        add_dummy_endnode = False
        if len(endnodes) > 1:
            # if this graph has multiple end nodes: create a single end node
            add_dummy_endnode = True
        elif head_inedges and len(endnodes) == 1 and endnodes[0] not in list(graph.predecessors(head)):
            # special case: there are in-edges to head, but the only end node is not a predecessor to head.
            # in this case, we will want to put the end node and a predecessor of the head into the same region.
            add_dummy_endnode = True

        if add_dummy_endnode:
            # we need a copy of the graph!
            graph_copy = networkx.DiGraph(graph_copy)
            dummy_endnode = "DUMMY_ENDNODE"
            for endnode in endnodes:
                graph_copy.add_edge(endnode, dummy_endnode)
            endnodes = [dummy_endnode]
        else:
            dummy_endnode = None

        # compute dominator tree
        doms = networkx.immediate_dominators(graph_copy, head)

        # compute post-dominator tree
        inverted_graph = shallow_reverse(graph_copy)
        postdoms = networkx.immediate_dominators(inverted_graph, endnodes[0])

        # dominance frontiers
        df = networkx.algorithms.dominance_frontiers(graph_copy, head)

        # visit the nodes in post-order
        for node in networkx.dfs_postorder_nodes(graph_copy, source=head):
            if node is dummy_endnode:
                # skip the dummy endnode
                continue
            if cyclic and node is head:
                continue

            out_degree = graph_copy.out_degree[node]
            if out_degree == 0:
                # the root element of the region hierarchy should always be a GraphRegion,
                # so we transform it into one, if necessary
                if graph_copy.in_degree(node) == 0 and not isinstance(node, GraphRegion):
                    subgraph = networkx.DiGraph()
                    subgraph.add_node(node)
                    self._abstract_acyclic_region(
                        graph,
                        GraphRegion(node, subgraph, None, None, False, None, cyclic_ancestor=cyclic),
                        [],
                        secondary_graph=secondary_graph,
                    )
                continue

            # test if this node is an entry to a single-entry, single-successor region
            levels = 0
            postdom_node = postdoms.get(node, None)
            while postdom_node is not None:
                if (node, postdom_node) not in failed_region_attempts and self._check_region(
                    graph_copy, node, postdom_node, doms, df
                ):
                    frontier = [postdom_node]
                    region = self._compute_region(
                        graph_copy, node, frontier, dummy_endnode=dummy_endnode, cyclic_ancestor=cyclic
                    )
                    if region is not None:
                        # update region.graph_with_successors
                        if secondary_graph is not None:
                            if self._complete_successors:
                                for nn in list(region.graph_with_successors.nodes):
                                    original_successors = secondary_graph.successors(nn)
                                    for succ in original_successors:
                                        if not region.graph_with_successors.has_edge(nn, succ):
                                            region.graph_with_successors.add_edge(nn, succ)
                                            region.successors.add(succ)
                            else:
                                for nn in list(region.graph_with_successors.nodes):
                                    original_successors = secondary_graph.successors(nn)
                                    for succ in original_successors:
                                        if succ not in graph_copy:
                                            # the successor wasn't added to the graph because it does not belong
                                            # to the frontier. we backpatch the successor graph here.
                                            region.graph_with_successors.add_edge(nn, succ)
                                            region.successors.add(succ)

                            # add edges between successors
                            for succ_0 in region.successors:
                                for succ_1 in region.successors:
                                    if succ_0 is not succ_1 and secondary_graph.has_edge(succ_0, succ_1):
                                        region.graph_with_successors.add_edge(succ_0, succ_1)

                        # l.debug("Walked back %d levels in postdom tree.", levels)
                        l.debug("Node %r, frontier %r.", node, frontier)
                        # l.debug("Identified an acyclic region %s.", self._dbg_block_list(region.graph.nodes()))
                        self._abstract_acyclic_region(
                            graph, region, frontier, dummy_endnode=dummy_endnode, secondary_graph=secondary_graph
                        )
                        # assert dummy_endnode not in graph
                        return True

                failed_region_attempts.add((node, postdom_node))
                if not dominates(doms, node, postdom_node):
                    break
                if postdom_node is postdoms.get(postdom_node, None):
                    break
                postdom_node = postdoms.get(postdom_node, None)
                levels += 1
            # l.debug("Walked back %d levels in postdom tree and did not find anything for %r. Next.", levels, node)

        return False

    @staticmethod
    def _check_region(graph, start_node, end_node, doms, df):
        """

        :param graph:
        :param start_node:
        :param end_node:
        :param doms:
        :param df:
        :return:
        """

        # if the exit node is the header of a loop that contains the start node, the dominance frontier should only
        # contain the exit node.
        if not dominates(doms, start_node, end_node):
            frontier = df.get(start_node, set())
            for node in frontier:
                if node is not start_node and node is not end_node:
                    return False

        # no edges should enter the region.
        for node in df.get(end_node, set()):
            if dominates(doms, start_node, node) and node is not end_node:
                return False

        # no edges should leave the region.
        for node in df.get(start_node, set()):
            if node is start_node or node is end_node:
                continue
            if node not in df.get(end_node, set()):
                return False
            for pred in graph.predecessors(node):
                if dominates(doms, start_node, pred) and not dominates(doms, end_node, pred):
                    return False

        return True

    @staticmethod
    def _compute_region(graph, node, frontier, include_frontier=False, dummy_endnode=None, cyclic_ancestor=False):
        subgraph = networkx.DiGraph()
        frontier_edges = []
        queue = [node]
        traversed = set()

        while queue:
            node_ = queue.pop()
            if node_ in frontier:
                continue
            traversed.add(node_)
            subgraph.add_node(node_)

            for succ in graph.successors(node_):
                edge_data = graph.get_edge_data(node_, succ)

                if node_ in frontier and succ in traversed:
                    if include_frontier:
                        # if frontier nodes are included, do not keep traversing their successors
                        # however, if it has an edge to an already traversed node, we should add that edge
                        subgraph.add_edge(node_, succ, **edge_data)
                    else:
                        frontier_edges.append((node_, succ, edge_data))
                    continue

                if succ is dummy_endnode:
                    continue

                if succ in frontier and not include_frontier:
                    # skip all frontier nodes
                    frontier_edges.append((node_, succ, edge_data))
                    continue
                subgraph.add_edge(node_, succ, **edge_data)
                if succ in traversed:
                    continue
                queue.append(succ)

        if dummy_endnode is not None:
            frontier = {n for n in frontier if n is not dummy_endnode}

        if subgraph.number_of_nodes() > 1:
            subgraph_with_frontier = networkx.DiGraph(subgraph)
            for src, dst, edge_data in frontier_edges:
                if dst is not dummy_endnode:
                    subgraph_with_frontier.add_edge(src, dst, **edge_data)
            # assert dummy_endnode not in frontier
            # assert dummy_endnode not in subgraph_with_frontier
            return GraphRegion(
                node, subgraph, frontier, subgraph_with_frontier, False, None, cyclic_ancestor=cyclic_ancestor
            )
        return None

    def _abstract_acyclic_region(
        self, graph: networkx.DiGraph, region, frontier, dummy_endnode=None, secondary_graph=None
    ):
        in_edges = self._region_in_edges(graph, region, data=True)
        out_edges = self._region_out_edges(graph, region, data=True)

        nodes_set = set()
        for node_ in list(region.graph.nodes()):
            nodes_set.add(node_)
            if node_ is not dummy_endnode:
                graph.remove_node(node_)

        graph.add_node(region)

        for src, _, data in in_edges:
            if src not in nodes_set:
                graph.add_edge(src, region, **data)

        for _, dst, data in out_edges:
            if dst not in nodes_set:
                graph.add_edge(region, dst, **data)

        if frontier:
            for frontier_node in frontier:
                if frontier_node is not dummy_endnode:
                    graph.add_edge(region, frontier_node)

        if secondary_graph is not None:
            self._abstract_acyclic_region(secondary_graph, region, {})

    @staticmethod
    def _abstract_cyclic_region(
        graph: networkx.DiGraph,
        loop_nodes,
        head,
        normal_entries,
        abnormal_entries,
        normal_exit_node,
        abnormal_exit_nodes,
    ):
        region = GraphRegion(head, None, None, None, True, None)

        subgraph = networkx.DiGraph()
        region_outedges = []

        delayed_edges = []

        full_graph = networkx.DiGraph()

        for node in loop_nodes:
            subgraph.add_node(node)
            in_edges = list(graph.in_edges(node, data=True))
            out_edges = list(graph.out_edges(node, data=True))

            for src, dst, data in in_edges:
                full_graph.add_edge(src, dst, **data)
                if src in loop_nodes:
                    subgraph.add_edge(src, dst, **data)
                elif src == region:
                    subgraph.add_edge(head, dst, **data)
                elif src in normal_entries:
                    # graph.add_edge(src, region, **data)
                    delayed_edges.append((src, region, data))
                elif src in abnormal_entries:
                    data["region_dst_node"] = dst
                    # graph.add_edge(src, region, **data)
                    delayed_edges.append((src, region, data))
                else:
                    assert 0

            for src, dst, data in out_edges:
                full_graph.add_edge(src, dst, **data)
                if dst in loop_nodes:
                    subgraph.add_edge(src, dst, **data)
                elif dst == region:
                    subgraph.add_edge(src, head, **data)
                elif dst == normal_exit_node:
                    region_outedges.append((node, dst))
                    # graph.add_edge(region, dst, **data)
                    delayed_edges.append((region, dst, data))
                elif dst in abnormal_exit_nodes:
                    region_outedges.append((node, dst))
                    # data['region_src_node'] = src
                    # graph.add_edge(region, dst, **data)
                    delayed_edges.append((region, dst, data))
                else:
                    assert 0

        subgraph_with_exits = networkx.DiGraph(subgraph)
        for src, dst in region_outedges:
            subgraph_with_exits.add_edge(src, dst)
        region.graph = subgraph
        region.graph_with_successors = subgraph_with_exits
        if normal_exit_node is not None:
            region.successors = [normal_exit_node]
        else:
            region.successors = []
        region.successors += list(abnormal_exit_nodes)

        for succ_0 in region.successors:
            for succ_1 in region.successors:
                if succ_0 is not succ_1 and graph.has_edge(succ_0, succ_1):
                    region.graph_with_successors.add_edge(succ_0, succ_1)

        for node in loop_nodes:
            graph.remove_node(node)

        # add delayed edges
        graph.add_node(region)
        for src, dst, data in delayed_edges:
            graph.add_edge(src, dst, **data)

        region.full_graph = full_graph

        return region

    @staticmethod
    def _region_in_edges(graph, region, data=False):
        return list(graph.in_edges(region.head, data=data))

    @staticmethod
    def _region_out_edges(graph, region, data=False):
        out_edges = []
        for node in region.graph.nodes():
            out_ = graph.out_edges(node, data=data)
            for _, dst, data_ in out_:
                if dst in region.graph:
                    continue
                out_edges.append((region, dst, data_))
        return out_edges

    def _remove_node(self, graph: networkx.DiGraph, node):  # pylint:disable=no-self-use
        in_edges = [(src, dst, data) for (src, dst, data) in graph.in_edges(node, data=True) if src is not node]
        out_edges = [(src, dst, data) for (src, dst, data) in graph.out_edges(node, data=True) if dst is not node]

        # true case: it forms a region by itself :-)
        new_node = None if len(in_edges) <= 1 and len(out_edges) <= 1 else MultiNode([node])

        graph.remove_node(node)

        if new_node is not None:
            for src, _, data in in_edges:
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges:
                graph.add_edge(new_node, dst, **data)

    def _merge_nodes(
        self, graph: networkx.DiGraph, node_a, node_b, force_multinode=False
    ):  # pylint:disable=no-self-use
        in_edges = list(graph.in_edges(node_a, data=True))
        out_edges = list(graph.out_edges(node_b, data=True))

        if not force_multinode and len(in_edges) <= 1 and len(out_edges) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            new_node = MultiNode([node_a, node_b])

        graph.remove_node(node_a)
        graph.remove_node(node_b)

        if new_node is not None:
            graph.add_node(new_node)

            for src, _, data in in_edges:
                if src is node_b:
                    src = new_node
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges:
                if dst is node_a:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

        assert node_a not in graph
        assert node_b not in graph

    def _absorb_node(
        self, graph: networkx.DiGraph, node_mommy, node_kiddie, force_multinode=False
    ):  # pylint:disable=no-self-use
        in_edges_mommy = graph.in_edges(node_mommy, data=True)
        out_edges_mommy = graph.out_edges(node_mommy, data=True)
        out_edges_kiddie = graph.out_edges(node_kiddie, data=True)

        if not force_multinode and len(in_edges_mommy) <= 1 and len(out_edges_kiddie) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            new_node = MultiNode([node_mommy, node_kiddie])

        graph.remove_node(node_mommy)
        graph.remove_node(node_kiddie)

        if new_node is not None:
            graph.add_node(new_node)

            for src, _, data in in_edges_mommy:
                if src == node_kiddie:
                    src = new_node
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges_mommy:
                if dst == node_kiddie:
                    continue
                if dst == node_mommy:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

            for _, dst, data in out_edges_kiddie:
                if dst == node_mommy:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

        assert node_mommy not in graph
        assert node_kiddie not in graph

    def _ensure_jump_at_loop_exit_ends(self, node: Block | MultiNode) -> None:
        if isinstance(node, Block):
            if not node.statements:
                node.statements.append(
                    Jump(
                        None,
                        Const(None, None, node.addr + node.original_size, self.project.arch.bits),
                        ins_addr=node.addr,
                    )
                )
            else:
                if not isinstance(first_nonlabel_nonphi_statement(node), ConditionalJump) and not isinstance(
                    node.statements[-1],
                    (
                        Jump,
                        ConditionalJump,
                        IncompleteSwitchCaseHeadStatement,
                    ),
                ):
                    node.statements.append(
                        Jump(
                            None,
                            Const(None, None, node.addr + node.original_size, self.project.arch.bits),
                            ins_addr=node.addr,
                        )
                    )
        elif isinstance(node, MultiNode) and node.nodes:
            self._ensure_jump_at_loop_exit_ends(node.nodes[-1])

    @staticmethod
    def _dbg_block_list(blocks):
        return [(hex(b.addr) if hasattr(b, "addr") else repr(b)) for b in blocks]


register_analysis(RegionIdentifier, "RegionIdentifier")
