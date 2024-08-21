from typing import Any
from itertools import count
import copy
import logging

import ailment.expression
import networkx

from ailment import Block
from ailment.statement import Jump, ConditionalJump, Assignment, Return, Label
from ailment.expression import Const

from ..condition_processor import ConditionProcessor, EmptyBlockNotice
from ..graph_region import GraphRegion
from ..utils import remove_labels, to_ail_supergraph, calls_in_graph
from ..structuring.structurer_nodes import MultiNode, ConditionNode
from ..region_identifier import RegionIdentifier

_l = logging.getLogger(name=__name__)


class ReturnDuplicatorBase:
    """
    The base class for implementing Return Duplication as described in the SAILR paper.
    This base class describes the general algorithm for duplicating return regions in a graph.
    """

    # pylint:disable=unused-argument
    def __init__(
        self,
        func,
        node_idx_start: int = 0,
        max_calls_in_regions: int = 2,
        minimize_copies_for_regions: bool = True,
        ri: RegionIdentifier | None = None,
        **kwargs,
    ):
        self.node_idx = count(start=node_idx_start)
        self._max_calls_in_region = max_calls_in_regions
        self._minimize_copies_for_regions = minimize_copies_for_regions
        self._supergraph = None

        # this should also be set by the optimization passes initer
        self._func = func
        self._ri: RegionIdentifier | None = ri

    #
    # must implement these methods
    #

    def _should_duplicate_dst(self, src, dst, graph, dst_is_const_ret=False) -> bool:
        raise NotImplementedError()

    #
    # main analysis
    #

    def _check(self):
        # does this function have end points?
        return bool(self._func.endpoints), None

    def _analyze_core(self, graph: networkx.DiGraph) -> bool:
        """
        This function does the core checks and duplications to the graph passed.
        The return value is True if the graph was changed.
        """
        graph_changed = False
        endnode_regions = self._find_endnode_regions(graph)

        if self._minimize_copies_for_regions:
            # perform a second pass to minimize the number of copies by doing only a single copy
            # for connected in_edges that form a region
            endnode_regions = self._copy_connected_edge_components(endnode_regions, graph)

        # refresh the supergraph
        self._supergraph = to_ail_supergraph(graph)
        for region_head, (in_edges, region) in endnode_regions.items():
            is_single_const_ret_region = self._is_simple_return_graph(region)
            for in_edge in in_edges:
                pred_node = in_edge[0]
                if self._should_duplicate_dst(
                    pred_node, region_head, graph, dst_is_const_ret=is_single_const_ret_region
                ):
                    # every eligible pred gets a new region copy
                    self._copy_region([pred_node], region_head, region, graph)

            if region_head in graph and graph.in_degree(region_head) == 0:
                graph.remove_nodes_from(region)

            graph_changed = True

        return graph_changed

    def _find_endnode_regions(self, graph) -> dict[Any, tuple[list[tuple[Any, Any]], networkx.DiGraph]]:
        """
        Find all the regions that contain a node with no successors. These are the "end nodes" of the graph.
        """
        endnodes = [node for node in graph.nodes() if graph.out_degree[node] == 0]

        # to_update is keyed by the region head.
        # this is because different end nodes may lead to the same region head: consider the case of the typical "fork"
        # region where stack canary is checked in x86-64 binaries.
        end_node_regions: dict[Any, tuple[list[tuple[Any, Any]], networkx.DiGraph]] = {}

        for end_node in endnodes:
            in_edges = list(graph.in_edges(end_node))

            if len(in_edges) > 1:
                region = networkx.DiGraph()
                region.add_node(end_node)
                region_head = end_node
            elif len(in_edges) == 1:
                # back-trace until it reaches a node with two predecessors
                region, region_head = self._single_entry_region(graph, end_node)
                tmp_in_edges = graph.in_edges(region_head)
                # remove in_edges that are coming from a node inside the region
                in_edges = []
                for src, dst in tmp_in_edges:
                    if src not in region:
                        in_edges.append((src, dst))
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

            if any(self._is_indirect_jump_ailblock(src) for src, _ in in_edges):
                continue

            # to assure we are not copying like crazy, set a max amount of code (which is estimated in calls)
            # that can be copied in a region
            if calls_in_graph(region) > self._max_calls_in_region:
                continue

            end_node_regions[region_head] = in_edges, region

        return end_node_regions

    def _copy_region(self, pred_nodes, region_head, region, graph):
        # copy the entire return region
        copies = {}
        queue = [(pred_node, region_head) for pred_node in pred_nodes]
        while queue:
            pred, node = queue.pop(0)
            if node in copies:
                node_copy = copies[node]
            else:
                node_copy = copy.deepcopy(node)
                node_copy.idx = next(self.node_idx)
                self._fix_copied_node_labels(node_copy)
                copies[node] = node_copy

            # modify Jump.target_idx and ConditionalJump.{true,false}_target_idx accordingly
            graph.add_edge(pred, node_copy)
            try:
                last_stmt = ConditionProcessor.get_last_statement(pred)
                if isinstance(last_stmt, Jump):
                    if isinstance(last_stmt.target, Const) and last_stmt.target.value == node_copy.addr:
                        last_stmt.target_idx = node_copy.idx
                elif isinstance(last_stmt, ConditionalJump):
                    if isinstance(last_stmt.true_target, Const) and last_stmt.true_target.value == node_copy.addr:
                        last_stmt.true_target_idx = node_copy.idx
                    elif isinstance(last_stmt.false_target, Const) and last_stmt.false_target.value == node_copy.addr:
                        last_stmt.false_target_idx = node_copy.idx
            except EmptyBlockNotice:
                pass

            for succ in region.successors(node):
                queue.append((node_copy, succ))

        for pred_node in pred_nodes:
            # delete the old edge to the return node
            graph.remove_edge(pred_node, region_head)

    def _copy_connected_edge_components(
        self, endnode_regions: dict[Any, tuple[list[tuple[Any, Any]], networkx.DiGraph]], graph: networkx.DiGraph
    ):
        updated_regions = endnode_regions.copy()
        all_region_block_addrs = list(self._find_block_sets_in_all_regions(self._ri.region).values())
        for region_head, (in_edges, region) in endnode_regions.items():
            is_single_const_ret_region = self._is_simple_return_graph(region)
            pred_nodes = [src for src, _ in in_edges]
            pred_subgraph = networkx.subgraph(graph, pred_nodes)
            components = list(networkx.weakly_connected_components(pred_subgraph))
            multi_node_components = [c for c in components if len(c) > 1]
            if not multi_node_components:
                continue

            # find components that have a node that should be duplicated
            candidate_components = []
            for nodes in multi_node_components:
                if any(
                    self._should_duplicate_dst(n, region_head, graph, dst_is_const_ret=is_single_const_ret_region)
                    for n in nodes
                ):
                    candidate_components.append(nodes)
            if not candidate_components:
                continue

            # we can only handle instances where components do not overlap
            overlapping_comps = set()
            for component in candidate_components:
                overlapping_comps &= component
            if overlapping_comps:
                continue

            # every component needs to form its own region with ONLY those nodes in the region
            duplicatable_components = []
            for component in candidate_components:
                comp_addrs = {n.addr for n in component}
                if comp_addrs in all_region_block_addrs:
                    duplicatable_components.append(component)

            new_in_edges = in_edges
            for nodes in duplicatable_components:
                self._copy_region(nodes, region_head, region, graph)
                if region_head in graph and graph.in_degree(region_head) == 0:
                    graph.remove_nodes_from(region)

                # update the in_edges to remove any nodes that have been copied
                new_in_edges = [edge for edge in new_in_edges if edge[0] not in nodes]

            if not new_in_edges:
                del updated_regions[region_head]
            else:
                updated_regions[region_head] = new_in_edges, region

        return updated_regions

    @staticmethod
    def _is_simple_return_graph(graph: networkx.DiGraph, max_assigns=1):
        """
        Checks if the provided graph is a graph that ONLY contains a "simple" return.
        If there were absolutely no bugs in angr, we could just check that a single return block exists.
        However, due to some propagation bugs, these cases can all happen and are all valid:
        1. [Jmp] -> [Jmp] -> [Ret]
        2. [Jmp] -> [Jmp, x=0] -> [Ret x]
        3. [Jmp] -> [Jmp, x=rdi] -> [Ret x]

        To deal with this, we need to do the sketchy checks we do below.
        """
        labeless_graph = to_ail_supergraph(remove_labels(graph))
        nodes = list(labeless_graph.nodes())
        if not nodes:
            return False

        # check if the graph is a single successor chain
        if not all(labeless_graph.out_degree(n) <= 1 for n in nodes):
            return False

        # collect the statements from the top node, make sure one exists
        root_nodes = [n for n in nodes if labeless_graph.in_degree(n) == 0]
        if len(root_nodes) != 1:
            return False

        root_node = root_nodes[0]
        queue = [root_node]
        stmts = []
        while queue:
            node = queue.pop(0)
            succs = list(labeless_graph.successors(node))
            queue += succs
            if node.statements:
                stmts += node.statements

        # all statements must be either a return, a jump, or an assignment
        type_white_list = (Return, Jump, Assignment)
        for stmt in stmts:
            if not isinstance(stmt, type_white_list):
                return False

        # gather all assignments
        assignments = [s for s in stmts if isinstance(s, Assignment)]
        has_assign = len(assignments) > 0
        if len(assignments) > max_assigns:
            return False

        # gather return stmts
        ret_stmt = stmts[-1]
        if not isinstance(ret_stmt, Return):
            if isinstance(ret_stmt, Jump):
                _l.warning("Found a jump at the end of a return graph, did function analysis fail?")
            return False

        ret_exprs = ret_stmt.ret_exprs
        # must be 1 or none
        if ret_exprs and len(ret_exprs) > 1:
            return False

        ret_expr = ret_exprs[0] if ret_exprs and len(ret_exprs) == 1 else None
        # stop early if there are no assignments at all and just jumps and rets, or a const ret
        if not has_assign:
            return True

        assign: Assignment = assignments[0]
        # const assignments are valid
        if isinstance(assign.src, Const):
            valid_assignment = ret_expr and ret_expr.likes(assign.dst)
        # assignments to registers from the stack are valid, since cases of these assignments
        # pop up across optimized binaries
        elif (
            isinstance(assign.dst, ailment.expression.Register)
            and isinstance(assign.src, ailment.expression.Load)
            and isinstance(assign.src.addr, ailment.expression.StackBaseOffset)
        ):
            valid_assignment = True
        else:
            valid_assignment = False

        return valid_assignment

    @staticmethod
    def _single_entry_region(graph, end_node) -> tuple[networkx.DiGraph, Any]:
        """
        Back track on the graph from `end_node` and find the longest chain of nodes where each node has only one
        predecessor and one successor (the second-to-last node may have two successors to account for the typical
        stack-canary-detection logic).

        :param end_node:    A node in the graph.
        :return:            A graph of nodes where the first node either has no predecessors or at least two
                            predecessors.
        """

        def _is_fork_node(node_) -> bool:
            """
            Check if the node and its successors form a "fork" region. A "fork" region is a region where:
            - The entry node has two successors,
            - Each successor has only the entry node as its predecessor.
            - Each successor has no successors.
            """

            succs = list(graph.successors(node_))
            if len(succs) != 2:
                return False
            for succ in succs:
                if graph.in_degree[succ] != 1:
                    return False
                if graph.out_degree[succ] != 0:
                    return False
            return True

        region = networkx.DiGraph()
        region.add_node(end_node)

        traversed = {end_node}
        region_head = end_node
        while True:
            preds = list(graph.predecessors(region_head))
            if len(preds) != 1:
                break
            second_to_last_node = region_head is end_node

            pred_node = preds[0]

            if pred_node in traversed:
                break

            if second_to_last_node:
                if _is_fork_node(pred_node):
                    # add the entire "fork" to the region
                    for succ in graph.successors(pred_node):
                        region.add_edge(pred_node, succ)
                elif graph.out_degree[pred_node] != 1:
                    # the predecessor has more than one successor, and it's not a fork node
                    break

                if graph.in_degree[pred_node] == 1:
                    # continue search
                    pass
                else:
                    region.add_edge(pred_node, region_head)
                    traversed.add(pred_node)
                    region_head = pred_node
                    break
            elif not second_to_last_node and graph.out_degree[pred_node] != 1:
                break

            region.add_edge(pred_node, region_head)
            traversed.add(pred_node)
            region_head = pred_node

        return region, region_head

    @staticmethod
    def _is_indirect_jump_ailblock(block: "Block") -> bool:
        if block.statements and isinstance(block.statements[-1], Jump):
            last_stmt = block.statements[-1]
            if not isinstance(last_stmt.target, Const):
                # it's an indirect jump (assuming the AIL block is properly optimized)
                return True
        return False

    @staticmethod
    def _is_single_return_stmt_region(region: networkx.DiGraph) -> bool:
        """
        Checks weather the provided region contains only one return statement. This stmt
        can be connected by many jumps, but none can be conditional. A valid case is:
        [Jmp] -> [Jmp] -> [Ret]
        """
        valid_stmt_types = (Return, Jump, Label)
        for node in region.nodes():
            if isinstance(node, Block):
                for stmt in node.statements:
                    if not isinstance(stmt, valid_stmt_types):
                        return False
        return True

    @staticmethod
    def _find_block_sets_in_all_regions(top_region: GraphRegion):
        def _unpack_block_type_to_addrs(node):
            if isinstance(node, Block):
                return {node.addr}
            elif isinstance(node, MultiNode):
                return {n.addr for n in node.nodes}
            elif isinstance(node, ConditionNode):
                return _unpack_block_type_to_addrs(node.true_node) | _unpack_block_type_to_addrs(node.false_node)
            return set()

        def _unpack_region_to_block_addrs(region: GraphRegion):
            region_addrs = set()
            for node in region.graph.nodes:
                if isinstance(node, (Block, MultiNode, ConditionNode)):
                    region_addrs |= _unpack_block_type_to_addrs(node)
                elif isinstance(node, GraphRegion):
                    region_addrs |= _unpack_region_to_block_addrs(node)

            return region_addrs

        def _unpack_every_region(region: GraphRegion, addrs_by_region: dict):
            addrs_by_region[region] = set()
            for node in region.graph.nodes:
                if isinstance(node, Block):
                    addrs_by_region[region].add(node.addr)
                elif isinstance(node, MultiNode):
                    for _node in node.nodes:
                        addrs_by_region[region].add(_node.addr)
                elif isinstance(node, ConditionNode):
                    addrs_by_region[region] |= _unpack_block_type_to_addrs(node.true_node)
                    addrs_by_region[region] |= _unpack_block_type_to_addrs(node.false_node)
                else:
                    addrs_by_region[region] |= _unpack_region_to_block_addrs(node)
                    _unpack_every_region(node, addrs_by_region)

        all_region_block_sets = {}
        _unpack_every_region(top_region, all_region_block_sets)
        return all_region_block_sets

    @staticmethod
    def _fix_copied_node_labels(block: Block):
        for i in range(len(block.statements)):  # pylint:disable=consider-using-enumerate
            stmt = block.statements[i]
            if isinstance(stmt, Label):
                # fix the default name by suffixing it with the new block ID
                new_name = stmt.name if stmt.name else f"Label_{stmt.ins_addr:x}"
                if stmt.block_idx is not None:
                    suffix = f"__{stmt.block_idx}"
                    if new_name.endswith(suffix):
                        new_name = new_name[: -len(suffix)]
                else:
                    new_name = stmt.name
                new_name += f"__{block.idx}"

                block.statements[i] = Label(stmt.idx, new_name, stmt.ins_addr, block_idx=block.idx, **stmt.tags)
