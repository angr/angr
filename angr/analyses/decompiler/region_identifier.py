from __future__ import annotations

import logging
from collections import defaultdict, deque
from collections.abc import Iterable
from itertools import count
from typing import Any, Literal, cast, overload

import networkx

from angr.ailment import Block, Manager
from angr.ailment.expression import Const
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.analysis import Analysis, register_analysis
from angr.errors import AngrRuntimeError
from angr.knowledge_plugins.functions.function import Function
from angr.utils.doms import IncrementalDominators
from angr.utils.graph import GraphUtils, dfs_back_edges, dominates, subgraph_between_nodes

from .condition_processor import ConditionProcessor
from .region_overlay import OverlayManager, RegionOverlay
from .structurer_nodes import ConditionNode, IncompleteSwitchCaseHeadStatement, MultiNode
from .utils import copy_graph, first_nonlabel_nonphi_statement

l = logging.getLogger(name=__name__)


# an ever-incrementing counter
CONDITIONNODE_ADDR = count(0xFF000000)

type TNode = Block | RegionOverlay | MultiNode | ConditionNode
type TGraph = "networkx.DiGraph[TNode]"


class RegionIdentifier(Analysis):
    """
    A region is a single-entry-single-exit subgraph of control flow. The region identifier recursively identifies the
    smallest possible regions within a function graph and creates a RegionOverlay object whose nodes are either Blocks
    or RegionOverlays.

    Note, that the analysis may modify the graph in-place. If you want to keep the original graph,
    set the `update_graph` parameter to False.
    """

    def __init__(
        self,
        func: Function,
        cond_proc: ConditionProcessor | None = None,
        graph: networkx.DiGraph[Block] | None = None,
        ail_manager: Manager | None = None,
        update_graph=True,
        largest_successor_tree_outside_loop=True,
        force_loop_single_exit=True,
        refine_loops_with_single_successor=False,
        expose_loop_head_backedges=False,
        entry_node_addr: tuple[int, int | None] | None = None,
    ):
        self.function = func
        self.entry_node_addr: tuple[int, int | None] | None = (
            entry_node_addr if entry_node_addr is not None else (func.addr, None) if func is not None else None
        )
        self.ail_manager = ail_manager if ail_manager is not None else Manager()
        self.cond_proc = (
            cond_proc
            if cond_proc is not None
            else ConditionProcessor(
                self.project.arch
                if getattr(self, "project", None) is not None
                else None,  # it's only None in test cases
                self.ail_manager,
            )
        )

        graph = graph if graph is not None else self.project.analyses.Clinic(func).graph
        assert graph is not None
        if not update_graph:
            # copy the graph so updates don't affect the original graph
            graph = copy_graph(graph)  # type: ignore

        self.region: RegionOverlay | None = None
        self.overlay_manager: OverlayManager | None = None
        self._start_node = None
        self._loop_headers: list | None = None
        self.regions_by_block_addrs = []
        self._largest_successor_tree_outside_loop = largest_successor_tree_outside_loop
        self._force_loop_single_exit = force_loop_single_exit
        self._refine_loops_with_single_successor = refine_loops_with_single_successor
        self._expose_loop_head_backedges = expose_loop_head_backedges
        # we keep a dictionary of node and their traversal order in a quasi-topological traversal and update this
        # dictionary as we update the graph
        self._node_order: dict[Any, tuple[int, int]] = {}

        self._graph = self._analyze(graph)

    @staticmethod
    def slice_graph(graph, node, frontier, include_frontier=False) -> TGraph:
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

    def _analyze(self, block_graph: networkx.DiGraph[Block]) -> TGraph:
        shared_graph = cast(TGraph, self._pick_one_connected_component(block_graph, as_copy=True))

        # preprocess: make it a super graph
        self._make_supergraph(shared_graph)

        # the shared graph stays intact from here on (except for in-place block-statement rewrites); regions are
        # overlays on it. region identification collapses a separate working graph.
        self.overlay_manager = OverlayManager(shared_graph, expose_loop_head_backedges=self._expose_loop_head_backedges)
        graph = cast(TGraph, networkx.DiGraph(shared_graph))

        self._start_node = self._get_start_node(graph)
        self._node_order = self._compute_node_order(graph)
        self.region = self._make_regions(graph)

        # make regions into block address lists
        self.regions_by_block_addrs = self._make_regions_by_block_addrs()
        return graph

    def _pick_one_connected_component(
        self, digraph: networkx.DiGraph[Block], as_copy: bool = False
    ) -> networkx.DiGraph[Block]:
        g = networkx.Graph(digraph)
        components: list[set[Block]] = list(networkx.connected_components(g))
        if len(components) <= 1:
            return networkx.DiGraph(digraph) if as_copy else digraph

        the_component = None
        largest_component = None
        for component in components:
            if largest_component is None or len(component) > len(largest_component):
                largest_component = component
            if any((block.addr, block.idx) == self.entry_node_addr for block in component):
                the_component = component
                break

        if the_component is None:
            the_component = largest_component

        assert the_component is not None
        return digraph.subgraph(the_component).to_directed()

    @staticmethod
    def _compute_node_order(graph: TGraph) -> dict[TNode, tuple[int, int]]:
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(graph)
        node_order = {}
        for i, n in enumerate(sorted_nodes):
            node_order[n] = i, 0
        return node_order

    def _sort_nodes(self, nodes: Iterable[TNode]) -> list[TNode]:
        """
        Sorts the nodes in the order specified in self._node_order.

        :param nodes:   A list or set of nodes to be sorted.
        :return:        A sorted list of nodes.
        """
        return sorted(nodes, key=lambda n: self._node_order[n])

    def _make_regions_by_block_addrs(self) -> list[list[tuple[int, int | None]]]:
        """
        Creates a list of addr lists representing each region without recursion. A single region is defined
        as a set of only blocks, no Graphs containing nested regions. The list contains the address of each
        block in the region, including the heads of each recursive region.

        :return: List of addr lists
        """

        assert self.region is not None
        work_list: list[RegionOverlay] = [self.region]
        block_only_regions = []
        seen_regions = set()
        while work_list:
            children_regions: list[RegionOverlay] = []
            for region in work_list:
                children_blocks = []
                for node in region.members:
                    if isinstance(node, Block):
                        children_blocks.append((node.addr, node.idx))
                    elif isinstance(node, MultiNode):
                        children_blocks += [(n.addr, node.idx) for n in node.nodes]
                    elif isinstance(node, RegionOverlay):
                        if node not in seen_regions:
                            children_regions.append(node)
                            children_blocks.append(
                                (node.head.addr, node.head.idx if hasattr(node.head, "idx") else None)
                            )
                            seen_regions.add(node)
                    else:
                        continue

                if children_blocks:
                    block_only_regions.append(children_blocks)

            work_list = children_regions

        return block_only_regions

    def _get_start_node(self, graph: TGraph):
        try:
            return next(n for n in graph.nodes() if graph.in_degree(n) == 0)
        except StopIteration:
            pass

        if self.entry_node_addr is not None:
            try:
                return next(
                    n
                    for n in graph.nodes()
                    if (
                        (n.addr, n.idx) == self.entry_node_addr
                        if isinstance(n, Block)
                        else n.addr == self.entry_node_addr[0]
                    )
                )
            except StopIteration as ex:
                raise AngrRuntimeError("Cannot find the start node from the graph!") from ex
        raise AngrRuntimeError("Cannot find the start node from the graph!")

    def _get_entry_node(self, graph: TGraph):
        if self.entry_node_addr is None:
            return None
        return next(
            (
                n
                for n in graph.nodes()
                if (
                    (n.addr, n.idx) == self.entry_node_addr
                    if isinstance(n, Block)
                    else n.addr == self.entry_node_addr[0]
                )
            ),
            None,
        )

    def _make_supergraph(self, graph: TGraph):
        entry_node = None
        if self.entry_node_addr is not None:
            entry_node = next(iter(nn for nn in graph if nn.addr == self.entry_node_addr[0]), None)

        # Worklist-driven single pass (see to_ail_supergraph for the rationale): only re-examine nodes whose in/out
        # degree could have changed (the merged node and its neighbors) instead of restarting a full edge scan after
        # every merge or removal, which is quadratic in the number of nodes.
        worklist: deque = deque(graph.nodes())
        while worklist:
            src = worklist.popleft()
            if src not in graph:
                # already merged away or removed
                continue
            for dst in list(graph.successors(src)):
                if entry_node is not None and dst is entry_node:
                    # the entry node must be kept instead of merged with its predecessor (which can happen in real
                    # binaries! e.g., 444a401b900eb825f216e95111dcb6ef94b01a81fc7b88a48599867db8c50365, function
                    # 0x1802BEA28, block 0x1802BEA05 and 0x1802BEA28)
                    continue

                type_ = graph.edges[src, dst].get("type", None)
                merged_node = None
                if type_ == "fake_return":
                    if graph.out_degree(src) == 1 and graph.in_degree(dst) == 1:
                        merged_node = self._merge_nodes(graph, src, dst, force_multinode=True)
                elif type_ == "call":
                    graph.remove_node(dst)
                    # src lost a successor, so it (and its predecessors) may now be mergeable
                    worklist.append(src)
                    worklist.extend(graph.predecessors(src))
                    break
                elif (
                    type_ == "transition"
                    and graph.out_degree(src) == 1
                    and graph.in_degree(dst) == 1
                    and src is not dst
                    and not self._block_ends_with_indirect_jump_or_call(dst)
                ):
                    merged_node = self._merge_nodes(graph, src, dst, force_multinode=True)

                if merged_node is not None:
                    # update the entry_node if necessary
                    if entry_node is not None and entry_node is src:
                        entry_node = merged_node
                    # the merged node and its neighbors may now be mergeable
                    worklist.append(merged_node)
                    worklist.extend(graph.predecessors(merged_node))
                    worklist.extend(graph.successors(merged_node))
                    break

    def _find_loop_headers(self, graph: TGraph) -> list[TNode]:
        assert self._start_node is not None
        heads = list({t for _, t in dfs_back_edges(graph, self._start_node)})
        return self._sort_nodes(heads)

    def _find_initial_loop_nodes(self, graph: TGraph, head: TNode) -> set[TNode]:
        assert self._start_node is not None
        # TODO optimize
        latching_nodes = {s for s, t in dfs_back_edges(graph, self._start_node) if t == head}
        loop_subgraph = self.slice_graph(graph, head, latching_nodes, include_frontier=True)

        # special case: any node with more than two non-self successors is probably the head of a switch-case. we
        # should include all successors into the loop subgraph.
        # we must be extra careful here to not include nodes that are reachable from outside the loop subgraph. an
        # example is in binary 064e1d62c8542d658d83f7e231cc3b935a1f18153b8aea809dcccfd446a91c93, loop 0x40d7b0 should
        # not include block 0x40d9d5 because this node has a out-of-loop-body predecessor (block 0x40d795).
        #
        # another special case: any node with two non-self successors where one of them is an identified jump table
        # head is likely the head of a switch-case. we should include all successors in the loop subgraph if these
        # successors do not have out-of-loop-body predecessors.
        # example: binary cb30d69b24245bf2ecdc9e7f53bbad19159999970b6d82c0c00c7d32d9e37aa4 , function 0x414cb0, block
        # 0x4046e4.
        cfg_model = self.kb.cfgs.get_most_accurate()
        jump_tables = cfg_model.jump_tables if cfg_model is not None else {}
        while True:
            updated = False
            for node in list(loop_subgraph):
                nonself_successors = [succ for succ in graph.successors(node) if succ is not node]
                if len(nonself_successors) > 2 or (
                    len(nonself_successors) == 2 and any(succ.addr in jump_tables for succ in nonself_successors)
                ):
                    for succ in nonself_successors:
                        if not loop_subgraph.has_edge(node, succ) and all(
                            pred in loop_subgraph for pred in graph.predecessors(succ)
                        ):
                            updated = True
                            loop_subgraph.add_edge(node, succ)
            if not updated:
                break

        return set(loop_subgraph)

    def _refine_loop(
        self, graph: TGraph, head: TNode, initial_loop_nodes: set[TNode], initial_exit_nodes: set[TNode]
    ) -> tuple[set[TNode], set[TNode]]:
        if (self._refine_loops_with_single_successor and len(initial_exit_nodes) == 0) or (
            not self._refine_loops_with_single_successor and len(initial_exit_nodes) <= 1
        ):
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

        sorted_refined_exit_nodes = self._sort_nodes(refined_exit_nodes)
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
            sorted_refined_exit_nodes = self._sort_nodes(sorted_refined_exit_nodes)

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

    def _make_regions(self, graph: TGraph) -> RegionOverlay:
        assert self.overlay_manager is not None
        root = self.overlay_manager.root
        structured_loop_headers = set()
        new_regions: list[RegionOverlay] = []

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

        root.head = self._get_start_node(graph)
        new_regions.append(root)

        l.debug("Identified %d loop regions.", len(structured_loop_headers))
        l.debug("No more loops left. Start structuring acyclic regions.")
        # No more loops left. Structure acyclic regions.
        while new_regions:
            region = new_regions.pop(0)
            head = region.head
            # collapse a working copy of the region body during acyclic region identification; for the root region,
            # the phase-1 working graph already matches its member-level view
            subgraph = graph if region is root else cast(TGraph, networkx.DiGraph(region.view()))

            failed_region_attempts = set()
            while self._make_acyclic_region(head, subgraph, region, failed_region_attempts, region.cyclic):
                if head not in subgraph:
                    # update head
                    head = next(iter(n for n in subgraph.nodes() if n.addr == head.addr))

            head = next(iter(n for n in subgraph.nodes() if n.addr == head.addr))
            region.head = head

        if len(graph) == 1:
            (res,) = graph.nodes
            if isinstance(res, RegionOverlay):
                return res
        root.head = self._get_start_node(graph)
        return root

    #
    # Cyclic regions
    #

    def _make_cyclic_region(self, head: TNode, graph: TGraph):
        original_entry = self._get_entry_node(graph)

        l.debug("Found cyclic region at %#08x", head.addr)
        initial_loop_nodes = self._find_initial_loop_nodes(graph, head)
        l.debug("Initial loop nodes %s", self._dbg_block_list(initial_loop_nodes))

        # Make sure no other loops are contained in the current loop
        assert self._loop_headers is not None
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
            graph,
            refined_loop_nodes,
            head,
            normal_entries,
            abnormal_entries,
            normal_exit_node,
            abnormal_exit_nodes,
            self._node_order,
        )
        assert region.graph is not None
        if region.successors is not None and len(region.successors) > 1 and self._force_loop_single_exit:
            # multi-successor region. refinement is required
            self._refine_loop_successors_to_guarded_successors(region, graph)

        # if the head node is in the graph and it's not the head of the graph, we will need to update the head node
        # address.
        if original_entry is not None and original_entry in region.graph and region.head is not original_entry:
            assert head.addr is not None
            self.entry_node_addr = (head.addr, None)
            # FIXME: the identified region will probably be incorrect. we may need to add a jump block that jumps to
            #  original_entry.

        return region

    def _refine_loop_successors_to_guarded_successors(self, region: RegionOverlay, graph: TGraph):
        """
        If there are multiple successors of a loop, convert them into guarded successors. Eventually there should be
        only one loop successor. This is used in the DREAM structuring algorithm.

        :param region:                  The cyclic region to refine.
        :param networkx.DiGraph graph:  The current graph that is being structured.
        :return:                        None
        """
        assert self.overlay_manager is not None
        if len(region.successor_nodes()) <= 1:
            return

        # recover reaching conditions
        self.cond_proc.recover_reaching_conditions(region, with_successors=True)

        # successor_nodes() is a set. Its iteration order must not choose the semantic priority of the guard chain:
        # overlapping recovered conditions use the first matching child, so identity-hash order would make output
        # and behavior process-dependent. RegionIdentifier's quasi-topological order is the canonical order here.
        successors = self._sort_nodes(region.successor_nodes())

        condnode_addr = next(CONDITIONNODE_ADDR)
        # create a new successor
        cond = ConditionNode(
            condnode_addr,
            None,
            self.cond_proc.reaching_conditions[successors[1]],
            successors[1],
            false_node=successors[0],
        )
        for succ in successors[2:]:
            cond: TNode = ConditionNode(
                condnode_addr,
                None,
                self.cond_proc.reaching_conditions[succ],
                succ,
                false_node=cond,
            )

        g = region.view_with_successors()
        mgr = self.overlay_manager
        parent = region.parent
        assert parent is not None

        # Resolve and validate every quotient edge before mutating either AIL or the shared graph. P-code instructions
        # may put an exit ConditionalJump in the middle of a block and a self-loop Jump at the end (REP is a common
        # example), so "last statement" is neither a sufficient owner lookup nor safe evidence for redirecting an
        # edge. If an edge has no exact semantic owner, abort this refinement instead of leaving stale AIL behind a
        # redirected CFG edge.
        transfer_rewrites: defaultdict[tuple[Block, int], set[str]] = defaultdict(set)
        condition_rewrites: list[tuple[ConditionNode, str]] = []
        condition_rewrite_set: set[tuple[ConditionNode, str]] = set()
        claimed_owners: dict[tuple[Any, ...], tuple[TNode, TNode]] = {}
        graph_redirects: dict[tuple[TNode, TNode], dict[str, Any]] = {}
        redirect_data_by_source: dict[TNode, dict[str, Any]] = {}
        for succ in successors:
            incoming_edges = sorted(g.in_edges(succ, data=True), key=lambda edge: self._node_order[edge[0]])
            for src, _, _data in incoming_edges:
                # The full cyclic-region view also contains edges between successor nodes. They are context for
                # reaching-condition recovery, not loop exits, and must not be rewritten as if they belonged to the
                # loop body.
                if src not in region.members:
                    continue

                # Modify the concrete sources that own this quotient edge. A source can itself be a RegionOverlay;
                # asking ConditionProcessor for that overlay's last statements returns no owner and previously left
                # the AIL jump stale. A ConditionNode is different again: its graph edges are represented by semantic
                # child references, not by the terminal statements inside those children.
                underlying_pairs = sorted(
                    region.underlying_edge_pairs(src, succ),
                    key=lambda edge: (self._node_order[edge[0]], self._node_order[edge[1]]),
                )
                if not underlying_pairs:
                    raise AngrRuntimeError(f"Loop-exit edge {src!r} -> {succ!r} has no underlying CFG edge")

                for concrete_src, concrete_dst in underlying_pairs:
                    edge = concrete_src, concrete_dst
                    if isinstance(concrete_src, ConditionNode):
                        owner_slots = [
                            ("condition", owner, attr)
                            for owner, attr in self._condition_successor_slots(concrete_src, (succ, concrete_dst))
                        ]
                    else:
                        owner_slots = [
                            ("transfer", block, stmt_idx, field)
                            for block, stmt_idx, field in self._transfer_slots_to_destination(
                                concrete_src, concrete_dst
                            )
                        ]
                    if not owner_slots:
                        raise AngrRuntimeError(
                            f"Loop-exit edge {concrete_src!r} -> {concrete_dst!r} has no exact AIL transfer owner"
                        )
                    for owner_slot in owner_slots:
                        previous_edge = claimed_owners.setdefault(owner_slot, edge)
                        if previous_edge != edge:
                            raise AngrRuntimeError(
                                f"Loop-exit edges {previous_edge!r} and {edge!r} share an ambiguous AIL transfer owner"
                            )
                        if owner_slot[0] == "condition":
                            condition_rewrite = owner_slot[1], owner_slot[2]
                            if condition_rewrite not in condition_rewrite_set:
                                condition_rewrite_set.add(condition_rewrite)
                                condition_rewrites.append(condition_rewrite)
                        else:
                            transfer_rewrites[(owner_slot[1], owner_slot[2])].add(owner_slot[3])
                    edge_data = dict(mgr.graph[concrete_src][concrete_dst])
                    graph_redirects.setdefault(edge, edge_data)
                    previous_data = redirect_data_by_source.setdefault(concrete_src, edge_data)
                    if previous_data != edge_data:
                        # A DiGraph has only one concrete_src -> cond edge. Silently applying both mappings would
                        # merge or overwrite attributes in traversal order and falsely claim that both old edges were
                        # preserved. Reject the unrepresentable refinement before changing statements or topology.
                        raise AngrRuntimeError(
                            f"Loop-exit edges from {concrete_src!r} have conflicting metadata that cannot be "
                            "represented by one guarded-successor edge"
                        )

        # add the condition node to the shared graph as a member of the enclosing region
        parent.add_node(cond)

        for owner, attr in condition_rewrites:
            child = getattr(owner, attr)
            setattr(owner, attr, cond)
            mgr._record(  # pylint:disable=protected-access
                lambda owner_=owner, attr_=attr, child_=child: setattr(owner_, attr_, child_)
            )

        for (block, stmt_idx), fields in transfer_rewrites.items():
            self._rewrite_transfer_slot_to_guard(block, stmt_idx, fields, condnode_addr)

        # redirect only the physical loop-exit edges whose exact semantic owners were proven above
        for u, v in graph_redirects:
            mgr.graph_remove_edge(u, v)
        for u, data in redirect_data_by_source.items():
            mgr.graph_add_edge(u, cond, **data)

        # connect the condition node to the (former) successors in the shared graph
        for succ in successors:
            entry = succ
            while isinstance(entry, RegionOverlay):
                entry = entry.head
            mgr.graph_add_edge(cond, entry)

        # modify the working graph
        graph.add_edge(region, cond)
        for succ in successors:
            edge_data = graph.get_edge_data(region, succ)
            graph.remove_edge(region, succ)
            graph.add_edge(cond, succ, **edge_data)

        # compute the node order of newly created nodes
        self._node_order[region] = region_node_order = min(self._node_order[node_] for node_ in region.members)
        self._node_order[cond] = region_node_order[0], region_node_order[1] + 1

    @classmethod
    def _condition_successor_slots(
        cls, node: ConditionNode, destinations: Iterable[TNode]
    ) -> list[tuple[ConditionNode, str]]:
        destinations = tuple(destinations)
        slots = []
        for attr in ("true_node", "false_node"):
            child = getattr(node, attr)
            if any(child is destination for destination in destinations):
                slots.append((node, attr))
            elif isinstance(child, ConditionNode):
                slots.extend(cls._condition_successor_slots(child, destinations))
        return slots

    @staticmethod
    def _iter_transfer_statement_slots(node: TNode):
        if isinstance(node, Block):
            for stmt_idx, stmt in enumerate(node.statements):
                if isinstance(stmt, (Jump, ConditionalJump)):
                    yield node, stmt_idx, stmt
        elif isinstance(node, MultiNode):
            for child in node.nodes:
                yield from RegionIdentifier._iter_transfer_statement_slots(child)

    def _transfer_target_matches_destination(self, source: TNode, target, target_idx, destination: TNode) -> bool:
        if not isinstance(target, Const):
            return False
        if target.value != getattr(destination, "addr", None):
            return False
        destination_idx = getattr(destination, "idx", None)
        if target_idx is not None:
            return destination_idx is not None and target_idx == destination_idx

        # Address-only AIL targets are exact only when the concrete CFG has a unique destination at that address.
        # Otherwise two same-address nodes could both claim the same statement field during preflight.
        assert self.overlay_manager is not None
        matching_destinations = [
            candidate
            for candidate in self.overlay_manager.graph.successors(source)
            if getattr(candidate, "addr", None) == target.value
        ]
        return len(matching_destinations) == 1 and matching_destinations[0] is destination

    def _transfer_slots_to_destination(self, source: TNode, destination: TNode) -> list[tuple[Block, int, str]]:
        slots = []
        for block, stmt_idx, stmt in self._iter_transfer_statement_slots(source):
            if isinstance(stmt, Jump):
                if self._transfer_target_matches_destination(source, stmt.target, stmt.target_idx, destination):
                    slots.append((block, stmt_idx, "target"))
            else:
                if self._transfer_target_matches_destination(
                    source, stmt.true_target, stmt.true_target_idx, destination
                ):
                    slots.append((block, stmt_idx, "true_target"))
                if self._transfer_target_matches_destination(
                    source, stmt.false_target, stmt.false_target_idx, destination
                ):
                    slots.append((block, stmt_idx, "false_target"))
        return slots

    def _rewrite_transfer_slot_to_guard(
        self, block: Block, stmt_idx: int, fields: set[str], condnode_addr: int
    ) -> None:
        assert self.overlay_manager is not None
        stmt = block.statements[stmt_idx]

        def guard_target():
            return Const(self.ail_manager.next_atom(), condnode_addr, self.project.arch.bits)

        if isinstance(stmt, Jump):
            assert fields == {"target"}
            new_stmt = Jump(
                stmt.idx,
                guard_target(),
                target_idx=None,
                transfer_kind=getattr(stmt, "transfer_kind", "unknown"),
                **stmt.tags,
            )
        else:
            assert isinstance(stmt, ConditionalJump)
            assert fields <= {"true_target", "false_target"}
            new_stmt = ConditionalJump(
                stmt.idx,
                stmt.condition,
                guard_target() if "true_target" in fields else stmt.true_target,
                guard_target() if "false_target" in fields else stmt.false_target,
                true_target_idx=None if "true_target" in fields else stmt.true_target_idx,
                false_target_idx=None if "false_target" in fields else stmt.false_target_idx,
                **stmt.tags,
            )

        block.statements[stmt_idx] = new_stmt
        self.overlay_manager._record(  # pylint:disable=protected-access
            lambda block_=block, stmt_idx_=stmt_idx, stmt_=stmt: block_.statements.__setitem__(stmt_idx_, stmt_)
        )

    #
    # Acyclic regions
    #

    def _make_acyclic_region(
        self,
        head: TNode,
        graph: TGraph,
        parent_region: RegionOverlay,
        failed_region_attempts: set[tuple[TNode, TNode]],
        cyclic: bool,
    ):
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
            dummy_endnode = Block(-1, -1)
            for endnode in endnodes:
                graph_copy.add_edge(endnode, dummy_endnode)
            endnodes = [dummy_endnode]
        else:
            dummy_endnode = None

        # dominators and post-dominators, computed incrementally
        doms = IncrementalDominators(graph_copy, head)
        postdoms = IncrementalDominators(graph_copy, endnodes[0], post=True)

        # visit the nodes in post-order
        region_created = False
        for node in list(GraphUtils.dfs_postorder_nodes_deterministic(graph_copy, head)):
            if node is dummy_endnode:
                # skip the dummy endnode
                continue
            if cyclic and node is head:
                continue
            if node not in graph_copy:
                continue

            out_degree = graph_copy.out_degree[node]
            if out_degree == 0:
                # the root element of the region hierarchy should always be a region,
                # so we transform it into one, if necessary
                if graph_copy.in_degree(node) == 0 and not isinstance(node, RegionOverlay):
                    region = parent_region.create_subregion(node, {node}, cyclic=False, cyclic_ancestor=cyclic)
                    self._abstract_acyclic_region(
                        graph,
                        region,
                        set(),
                        self._node_order,
                    )
                continue

            # test if this node is an entry to a single-entry, single-successor region
            levels = 0
            postdom_node = postdoms.idom(node)
            while postdom_node is not None:
                if (node, postdom_node) not in failed_region_attempts and self._check_region(
                    graph_copy, node, postdom_node, doms
                ):
                    frontier = {postdom_node}
                    region_nodes = self._compute_region_nodes(graph_copy, node, frontier, dummy_endnode=dummy_endnode)
                    if region_nodes is not None:
                        region = parent_region.create_subregion(
                            node, region_nodes, cyclic=False, cyclic_ancestor=cyclic
                        )
                        # note that successors of the new region (the frontier, plus loop exits when this region
                        # nests inside a cyclic region) are derived from the shared graph on demand; no successor
                        # graph bookkeeping is needed here

                        # l.debug("Walked back %d levels in postdom tree.", levels)
                        l.debug("Node %r, frontier %r.", node, frontier)
                        # l.debug("Identified an acyclic region %s.", self._dbg_block_list(region_nodes))
                        self._abstract_acyclic_region(
                            graph,
                            region,
                            frontier,
                            self._node_order,
                            dummy_endnode=dummy_endnode,
                        )
                        # assert dummy_endnode not in graph
                        region_created = True
                        # we created a new region to replace one or more nodes in the graph.
                        replaced_nodes = region_nodes
                        # update graph_copy; doms and postdoms are updated as well because they hold references to
                        # graph_copy internally.
                        if graph_copy is not graph:
                            self._update_graph(graph_copy, region, replaced_nodes)
                        doms.graph_updated(region, replaced_nodes, region.head)
                        postdoms.graph_updated(region, replaced_nodes, region.head)
                        # break out of the inner loop
                        break

                failed_region_attempts.add((node, postdom_node))
                if not doms.dominates(node, postdom_node):
                    break
                if postdom_node is postdoms.idom(postdom_node):
                    break
                postdom_node = postdoms.idom(postdom_node)
                levels += 1
            # l.debug("Walked back %d levels in postdom tree and did not find anything for %r. Next.", levels, node)

        return region_created

    @staticmethod
    def _update_graph(graph: TGraph, new_region: RegionOverlay, replaced_nodes: set[TNode]) -> None:
        region_in_edges = RegionIdentifier._region_in_edges(graph, new_region, data=True)
        region_out_edges = RegionIdentifier._region_out_edges(graph, new_region, data=True)
        for node in replaced_nodes:
            graph.remove_node(node)
        graph.add_node(new_region)
        for src, _, data in region_in_edges:
            graph.add_edge(src, new_region, **data)
        for _, dst, data in region_out_edges:
            graph.add_edge(new_region, dst, **data)

    @staticmethod
    def _check_region(graph: TGraph, start_node: TNode, end_node: TNode, doms: IncrementalDominators) -> bool:
        """
        Determine the graph slice between start_node and end_node forms a good region.
        """

        # if the exit node is the header of a loop that contains the start node, the dominance frontier should only
        # contain the exit node.
        start_node_frontier = None
        end_node_frontier = None

        if not doms.dominates(start_node, end_node):
            start_node_frontier = doms.df(start_node)
            for node in start_node_frontier:
                if node is not start_node and node is not end_node:
                    return False

        # no edges should enter the region.
        end_node_frontier = doms.df(end_node)
        for node in end_node_frontier:
            if doms.dominates(start_node, node) and node is not end_node:
                return False

        if start_node_frontier is None:
            start_node_frontier = doms.df(start_node)

        # no edges should leave the region.
        for node in start_node_frontier:
            if node is start_node or node is end_node:
                continue
            if node not in end_node_frontier:
                return False
            for pred in graph.predecessors(node):
                if doms.dominates(start_node, pred) and not doms.dominates(end_node, pred):
                    return False

        return True

    @staticmethod
    def _compute_region_nodes(
        graph: TGraph,
        node: TNode,
        frontier: set[TNode],
        dummy_endnode: TNode | None = None,
    ) -> set[TNode] | None:
        """
        Collect the nodes of the region that starts at ``node`` and is delimited by ``frontier``, by traversing the
        working graph. Returns None if the region consists of just the starting node.
        """
        traversed = set()
        queue = [node]

        while queue:
            node_ = queue.pop()
            if node_ in frontier:
                continue
            traversed.add(node_)

            for succ in graph.successors(node_):
                if succ is dummy_endnode or succ in frontier or succ in traversed:
                    continue
                queue.append(succ)

        if len(traversed) > 1:
            return traversed
        return None

    @staticmethod
    def _abstract_acyclic_region(
        graph: TGraph,
        region: RegionOverlay,
        frontier: set[TNode],
        node_order: dict[TNode, tuple[int, int]],
        dummy_endnode: TNode | None = None,
    ):
        in_edges = RegionIdentifier._region_in_edges(graph, region, data=True)
        out_edges = RegionIdentifier._region_out_edges(graph, region, data=True)

        nodes_set = set()
        for node_ in list(region.members):
            nodes_set.add(node_)
            if node_ is not dummy_endnode:
                graph.remove_node(node_)

        graph.add_node(region)
        node_order[region] = min(node_order[node_] for node_ in nodes_set)

        for src, _, data in in_edges:
            if src not in nodes_set:
                graph.add_edge(src, region, **data)

        for _, dst, data in out_edges:
            if dst not in nodes_set:
                graph.add_edge(region, dst, **data)

        for frontier_node in frontier:
            if frontier_node is not dummy_endnode:
                graph.add_edge(region, frontier_node)

    def _abstract_cyclic_region(
        self,
        graph: TGraph,
        loop_nodes: Iterable[TNode],
        head: TNode,
        normal_entries: set[TNode],
        abnormal_entries: set[TNode],
        normal_exit_node: TNode | None,
        abnormal_exit_nodes: set[TNode],
        node_order: dict[TNode, tuple[int, int]],
    ) -> RegionOverlay:
        loop_nodes = set(loop_nodes)
        region = self._parent_overlay_of(head).create_subregion(head, loop_nodes, cyclic=True)

        delayed_edges = []

        for node in loop_nodes:
            in_edges = list(graph.in_edges(node, data=True))
            out_edges = list(graph.out_edges(node, data=True))

            for src, _dst, data in in_edges:
                if src in loop_nodes:
                    pass
                elif src in normal_entries or src in abnormal_entries:
                    # graph.add_edge(src, region, **data)
                    delayed_edges.append((src, region, data))
                else:
                    assert 0

            for _src, dst, data in out_edges:
                if dst in loop_nodes:
                    pass
                elif dst == normal_exit_node or dst in abnormal_exit_nodes:
                    # graph.add_edge(region, dst, **data)
                    delayed_edges.append((region, dst, data))
                else:
                    assert 0

        for node in loop_nodes:
            graph.remove_node(node)

        # add delayed edges
        graph.add_node(region)
        for src, dst, data in delayed_edges:
            graph.add_edge(src, dst, **data)
        # update node order
        node_order[region] = node_order[head]

        return region

    def _parent_overlay_of(self, node: TNode) -> RegionOverlay:
        """Find the overlay that the given working-graph node is currently a direct member of."""
        if isinstance(node, RegionOverlay):
            assert node.parent is not None
            return node.parent
        assert self.overlay_manager is not None
        owner = self.overlay_manager.owner_of(node)
        assert owner is not None
        return owner

    @overload
    @staticmethod
    def _region_in_edges(
        graph: TGraph, region: RegionOverlay, data: Literal[True]
    ) -> list[tuple[TNode, TNode, dict[str, Any]]]: ...

    @overload
    @staticmethod
    def _region_in_edges(graph: TGraph, region: RegionOverlay, data: Literal[False]) -> list[tuple[TNode, TNode]]: ...

    @staticmethod
    def _region_in_edges(graph, region, data=False):
        return list(graph.in_edges(region.head, data=data))

    @staticmethod
    def _region_out_edges(graph, region: RegionOverlay, data=False):
        out_edges = []
        for node in region.members:
            out_ = graph.out_edges(node, data=data)
            for _, dst, data_ in out_:
                if dst in region.members:
                    continue
                out_edges.append((region, dst, data_))
        return out_edges

    @staticmethod
    def _block_ends_with_indirect_jump_or_call(node: TNode) -> bool:
        """Check if the last statement of a node is an indirect jump or a call."""
        last_block = node.nodes[-1] if isinstance(node, MultiNode) else node
        if isinstance(last_block, Block) and last_block.statements:
            last_stmt = last_block.statements[-1]
            if isinstance(last_stmt, Jump) and not isinstance(last_stmt.target, Const):
                return True
            if isinstance(last_stmt, ConditionalJump):
                return True
        return False

    @staticmethod
    def _merge_nodes(graph: TGraph, node_a: TNode, node_b: TNode, force_multinode: bool = False) -> MultiNode | None:
        in_edges = list(graph.in_edges(node_a, data=True))
        out_edges = list(graph.out_edges(node_b, data=True))

        if not force_multinode and len(in_edges) <= 1 and len(out_edges) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            nodes = []
            match node_a:
                case MultiNode():
                    nodes.extend(node_a.nodes)
                case Block():
                    nodes.append(node_a)
                case _:
                    raise TypeError(type(node_a))
            match node_b:
                case MultiNode():
                    nodes.extend(node_b.nodes)
                case Block():
                    nodes.append(node_b)
                case _:
                    raise TypeError(type(node_b))
            new_node = MultiNode(nodes)

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

        return new_node

    def _ensure_jump_at_loop_exit_ends(self, node: TNode) -> None:
        if isinstance(node, Block):
            if not node.statements:
                node.statements.append(
                    Jump(
                        self.ail_manager.next_atom(),
                        Const(self.ail_manager.next_atom(), node.addr + node.original_size, self.project.arch.bits),
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
                            self.ail_manager.next_atom(),
                            Const(
                                self.ail_manager.next_atom(),
                                node.addr + node.original_size,
                                self.project.arch.bits,
                            ),
                            ins_addr=node.addr,
                        )
                    )
        elif isinstance(node, MultiNode) and node.nodes:
            self._ensure_jump_at_loop_exit_ends(node.nodes[-1])

    @staticmethod
    def _dbg_block_list(blocks: Iterable[TNode]) -> list[str]:
        return [(hex(b.addr) if hasattr(b, "addr") and b.addr is not None else repr(b)) for b in blocks]

    #
    # Reducibility
    #

    def test_reducibility(self) -> bool:
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

    def _remove_self_loop(self, graph: TGraph) -> bool:
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

    def _merge_single_entry_node(self, graph: TGraph) -> bool:
        r = False

        while True:
            for node in networkx.dfs_postorder_nodes(graph):
                preds = list(graph.predecessors(node))
                if len(preds) == 1:
                    # merge the two nodes
                    (pred,) = preds
                    self._absorb_node(graph, pred, node)
                    r = True
                    break
            else:
                break

        return r

    def _remove_node(self, graph: TGraph, node: TNode):  # pylint:disable=no-self-use
        in_edges = [(src, dst, data) for (src, dst, data) in graph.in_edges(node, data=True) if src is not node]
        out_edges = [(src, dst, data) for (src, dst, data) in graph.out_edges(node, data=True) if dst is not node]

        if len(in_edges) <= 1 and len(out_edges) <= 1:
            new_node = None
        else:
            # true case: it forms a region by itself :-)
            assert isinstance(node, Block)
            new_node = MultiNode([node])

        graph.remove_node(node)

        if new_node is not None:
            for src, _, data in in_edges:
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges:
                graph.add_edge(new_node, dst, **data)

    @staticmethod
    def _absorb_node(graph: TGraph, node_mommy: TNode, node_kiddie: TNode, force_multinode: bool = False):
        in_edges_mommy = graph.in_edges(node_mommy, data=True)
        out_edges_mommy = graph.out_edges(node_mommy, data=True)
        out_edges_kiddie = graph.out_edges(node_kiddie, data=True)

        if not force_multinode and len(in_edges_mommy) <= 1 and len(out_edges_kiddie) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            assert isinstance(node_mommy, Block)
            assert isinstance(node_kiddie, Block)
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


register_analysis(RegionIdentifier, "RegionIdentifier")
