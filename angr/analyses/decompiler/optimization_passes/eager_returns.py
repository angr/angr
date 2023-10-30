from typing import Any, Tuple, Dict, List, TYPE_CHECKING, Optional
from itertools import count
import copy
import logging
import inspect

import networkx

from ailment import Block
from ailment.statement import Jump, ConditionalJump, Assignment, Statement, Return, Label
from ailment.expression import Const
from ailment.block_walker import AILBlockWalkerBase

from .optimization_pass import StructuringOptimizationPass
from ..condition_processor import ConditionProcessor, EmptyBlockNotice
from ..graph_region import GraphRegion
from ..utils import remove_labels, to_ail_supergraph
from ..structuring.structurer_nodes import MultiNode

if TYPE_CHECKING:
    from ailment.statement import Call


_l = logging.getLogger(name=__name__)


class AILCallCounter(AILBlockWalkerBase):
    """
    Helper class to count AIL Calls in a block
    """

    calls = 0

    def _handle_Call(self, stmt_idx: int, stmt: "Call", block: Optional["Block"]):
        self.calls += 1
        super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: "Call", stmt_idx: int, stmt: Statement, block: Optional[Block]):
        self.calls += 1
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)


class EagerReturnsSimplifier(StructuringOptimizationPass):
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

    ARCHES = None
    PLATFORMS = None
    NAME = "Duplicate return blocks to reduce goto statements"
    DESCRIPTION = inspect.cleandoc(__doc__[: __doc__.index(":ivar")])  # pylint:disable=unsubscriptable-object

    def __init__(
        self,
        func,
        # internal parameters that should be used by Clinic
        node_idx_start=0,
        # settings
        max_opt_iters=10,
        max_calls_in_regions=2,
        prevent_new_gotos=True,
        minimize_copies_for_regions=True,
        **kwargs,
    ):
        super().__init__(func, max_opt_iters=max_opt_iters, prevent_new_gotos=prevent_new_gotos, **kwargs)
        self._max_calls_in_region = max_calls_in_regions
        self._minimize_copies_for_regions = minimize_copies_for_regions

        self.node_idx = count(start=node_idx_start)
        self.analyze()

    def _check(self):
        # does this function have end points?
        if not self._func.endpoints:
            return False, None

        # TODO: More filtering
        return True, None

    def _analyze(self, cache=None):
        graph_changed = False
        endnode_regions = self._find_endnode_regions(self.out_graph)

        if self._minimize_copies_for_regions:
            # perform a second pass to minimize the number of copies by doing only a single copy
            # for connected in_edges that form a region
            endnode_regions = self._copy_connected_edge_components(endnode_regions, self.out_graph)

        for region_head, (in_edges, region) in endnode_regions.items():
            is_single_const_ret_region = self._is_single_constant_return_graph(region)
            for in_edge in in_edges:
                pred_node = in_edge[0]
                if self._should_duplicate_dst(
                    pred_node, region_head, self.out_graph, dst_is_const_ret=is_single_const_ret_region
                ):
                    # every eligible pred gets a new region copy
                    self._copy_region([pred_node], region_head, region, self.out_graph)

            if region_head in self.out_graph and self.out_graph.in_degree(region_head) == 0:
                self.out_graph.remove_nodes_from(region)

            graph_changed = True

        return graph_changed

    def _is_goto_edge(
        self,
        src: Block,
        dst: Block,
        graph: networkx.DiGraph = None,
        check_for_ifstmts=True,
        max_level_check=1,
    ):
        """
        This function only exists because a long-standing bug that sometimes reports the if-stmt addr
        above a goto edge as the goto src. Because of this, we need to check for predecessors above the goto and
        see if they are a goto. This needs to include Jump to deal with loops.
        """
        if check_for_ifstmts and graph is not None:
            blocks = [src]
            level_blocks = [src]
            for _ in range(max_level_check):
                new_level_blocks = []
                for lblock in level_blocks:
                    new_level_blocks += list(graph.predecessors(lblock))

                blocks += new_level_blocks
                level_blocks = new_level_blocks

            src_direct_parents = [p for p in graph.predecessors(src)]
            for block in blocks:
                if not block or not block.statements:
                    continue

                # special case if-stmts that are next to each other
                if block in src_direct_parents and isinstance(block.statements[-1], ConditionalJump):
                    continue

                if self._goto_manager.is_goto_edge(block, dst):
                    return True
        else:
            return self._goto_manager.is_goto_edge(src, dst)

        return False

    def _find_endnode_regions(self, graph):
        endnodes = [node for node in graph.nodes() if graph.out_degree[node] == 0]

        # to_update is keyed by the region head.
        # this is because different end nodes may lead to the same region head: consider the case of the typical "fork"
        # region where stack canary is checked in x86-64 binaries.
        end_node_regions: Dict[Any, Tuple[List[Tuple[Any, Any]], networkx.DiGraph]] = {}

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
            if self._number_of_calls_in(region) > self._max_calls_in_region:
                continue

            end_node_regions[region_head] = in_edges, region

        return end_node_regions

    def _should_duplicate_dst(self, src, dst, graph, dst_is_const_ret=False):
        # returns that are only returning a constant should be duplicated always;
        if dst_is_const_ret:
            return True

        # check above
        return self._is_goto_edge(src, dst, graph=graph, check_for_ifstmts=True)

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
        self, endnode_regions: Dict[Any, Tuple[List[Tuple[Any, Any]], networkx.DiGraph]], graph: networkx.DiGraph
    ):
        updated_regions = endnode_regions.copy()
        all_region_block_addrs = list(self._find_block_sets_in_all_regions(self._ri.region).values())
        for region_head, (in_edges, region) in endnode_regions.items():
            is_single_const_ret_region = self._is_single_constant_return_graph(region)
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
                new_in_edges = list(filter(lambda e: e[0] not in nodes, new_in_edges))

            if not new_in_edges:
                del updated_regions[region_head]
            else:
                updated_regions[region_head] = new_in_edges, region

        return updated_regions

    @staticmethod
    def _is_single_constant_return_graph(graph: networkx.DiGraph):
        """
        Check if the graph is a single block that returns a constant.
        TODO: update the naming of this function, as now it returns true if the return target
        is NOT a constant, but instead a graph with only returns and jumps.
        """
        labeless_graph = to_ail_supergraph(remove_labels(graph))
        nodes = list(labeless_graph.nodes())
        if not nodes:
            return False

        # check if the graph is a single successor chain
        if not all(labeless_graph.out_degree(n) <= 1 for n in nodes):
            return False

        # collect the statements from the top node
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
        ok_stmts = [s for s in stmts if isinstance(s, (Return, Jump, Assignment))]
        if len(ok_stmts) != len(stmts):
            return False

        # gather all assignments
        assignments = [s for s in stmts if isinstance(s, Assignment)]
        has_assign = len(assignments) > 0
        if len(assignments) > 1:
            return False

        # gather return stmts
        ret_stmt = stmts[-1]
        ret_exprs = ret_stmt.ret_exprs
        # must be 1 or none
        if ret_exprs and len(ret_exprs) > 1:
            return False

        ret_expr = ret_exprs[0] if ret_exprs and len(ret_exprs) == 1 else None
        # stop early if there are no assignments at all and just jumps and rets, or a const ret
        if not has_assign:
            return True

        # check if the assignment is assigning a constant
        assign: Assignment = assignments[0]
        if not isinstance(assign.src, Const):
            return False

        return ret_expr and ret_expr.likes(assign.dst)

    @staticmethod
    def _number_of_calls_in(graph: networkx.DiGraph) -> int:
        counter = AILCallCounter()
        for node in graph.nodes:
            counter.walk(node)

        return counter.calls

    @staticmethod
    def _single_entry_region(graph, end_node) -> Tuple[networkx.DiGraph, Any]:
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
        def _unpack_region_to_block_addrs(region: GraphRegion):
            region_addrs = set()
            for node in region.graph.nodes:
                if isinstance(node, Block):
                    region_addrs.add(node.addr)
                elif isinstance(node, MultiNode):
                    for _node in node.nodes:
                        region_addrs.add(_node.addr)
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
                else:
                    addrs_by_region[region] |= _unpack_region_to_block_addrs(node)
                    _unpack_every_region(node, addrs_by_region)

        all_region_block_sets = {}
        _unpack_every_region(top_region, all_region_block_sets)
        return all_region_block_sets
