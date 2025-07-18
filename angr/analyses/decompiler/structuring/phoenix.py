# pylint:disable=line-too-long,import-outside-toplevel,import-error,multiple-statements,too-many-boolean-expressions
# ruff: noqa: SIM102
from __future__ import annotations
from typing import Any, TYPE_CHECKING
from collections import defaultdict, OrderedDict
from enum import Enum
import logging

import networkx

import claripy
from angr.ailment.block import Block
from angr.ailment.statement import Statement, ConditionalJump, Jump, Label, Return
from angr.ailment.expression import Const, UnaryOp, MultiStatementExpression, BinaryOp

from angr.utils.graph import GraphUtils
from angr.utils.ail import is_phi_assignment, is_head_controlled_loop_block
from angr.knowledge_plugins.cfg import IndirectJump, IndirectJumpType
from angr.utils.constants import SWITCH_MISSING_DEFAULT_NODE_ADDR
from angr.utils.graph import dominates, to_acyclic_graph, dfs_back_edges
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.utils import (
    remove_last_statement,
    remove_last_statements,
    extract_jump_targets,
    switch_extract_cmp_bounds,
    switch_extract_cmp_bounds_from_condition,
    is_empty_or_label_only_node,
    has_nonlabel_nonphi_statements,
    first_nonlabel_nonphi_statement,
    switch_extract_bitwiseand_jumptable_info,
    switch_extract_switch_expr_from_jump_target,
)
from angr.analyses.decompiler.counters.call_counter import AILCallCounter
from angr.analyses.decompiler.node_replacer import NodeReplacer
from .structurer_nodes import (
    ConditionNode,
    SequenceNode,
    LoopNode,
    ConditionalBreakNode,
    BreakNode,
    ContinueNode,
    BaseNode,
    MultiNode,
    SwitchCaseNode,
    IncompleteSwitchCaseNode,
    EmptyBlockNotice,
    IncompleteSwitchCaseHeadStatement,
)
from .structurer_base import StructurerBase

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

l = logging.getLogger(__name__)
_DEBUG = False


class GraphChangedNotification(Exception):
    """
    A notification for graph that is currently worked on being changed. Once this notification is caught, the graph
    schema matching process for the current region restarts.
    """


class MultiStmtExprMode(str, Enum):
    """
    Mode of multi-statement expression creation during structuring.
    """

    NEVER = "Never"
    ALWAYS = "Always"
    MAX_ONE_CALL = "Only when less than one call"


class GraphEdgeFilter:
    """
    Filters away edges in a graph that are marked as deleted (outgoing-edges) during cyclic refinement.
    """

    def __init__(self, graph: networkx.DiGraph):
        self.graph = graph

    def __call__(self, src, dst) -> bool:
        d = self.graph[src][dst]
        return not d.get("cyclic_refinement_outgoing", False)


def _f(graph: networkx.DiGraph):
    return networkx.subgraph_view(graph, filter_edge=GraphEdgeFilter(graph))


class PhoenixStructurer(StructurerBase):
    """
    Structure a region using a structuring algorithm that is similar to the one in Phoenix decompiler (described in the
    "phoenix decompiler" paper). Note that this implementation has quite a few improvements over the original described
    version and *should not* be used to evaluate the performance of the original algorithm described in that paper.
    """

    NAME = "phoenix"

    def __init__(
        self,
        region,
        parent_map=None,
        condition_processor=None,
        func: Function | None = None,
        case_entry_to_switch_head: dict[int, int] | None = None,
        parent_region=None,
        improve_algorithm=False,
        use_multistmtexprs: MultiStmtExprMode = MultiStmtExprMode.MAX_ONE_CALL,
        multistmtexpr_stmt_threshold: int = 5,
        **kwargs,
    ):
        super().__init__(
            region,
            parent_map=parent_map,
            condition_processor=condition_processor,
            func=func,
            case_entry_to_switch_head=case_entry_to_switch_head,
            parent_region=parent_region,
            **kwargs,
        )

        # whitelist certain edges. removing these edges will destroy critical schemas, which will impact future
        # structuring cycles.
        # the set is populated during the analysis. _last_resort_refinement() will ensure not to remove any edges
        # who fall into these sets.
        self.whitelist_edges: set[tuple[int, int]] = set()
        # also whitelist certain nodes that are definitely header for switch-case constructs. they should not be merged
        # into another node before we successfully structure the entire switch-case.
        self.switch_case_known_heads: set[Block | BaseNode] = set()

        # whitelist certain nodes that should be treated as a tail node for do-whiles. these nodes should not be
        # absorbed into other SequenceNodes
        self.dowhile_known_tail_nodes: set = set()

        # in reimplementing the core phoenix algorithm from the phoenix decompiler paper, two types of changes were
        # made to the algorithm:
        # 1. Mandatory fixes to correct flaws we found in the algorithm
        # 2. Optional fixes to improve the results of already correct choices
        #
        # the improve_algorithm flag controls whether the optional fixes are applied. these are disabled by default
        # to be as close to the original algorithm as possible. for best results, enable this flag.
        self._improve_algorithm = improve_algorithm
        self._edge_virtualization_hints = []

        # for each region, we only convert a switch-case head into an IncompleteSwitchCaseNode once. this is to avoid
        # loops of creating and unpacking IncompleteSwitchCaseNode (when the entire switch-case construct is not yet
        # ready to be structured, e.g., default node has a successor A and all case nodes have a successor B).
        # TestDecompiler.test_decompiling_abnormal_switch_case_within_a_loop_with_redundant_jump captures this case.
        self._matched_incomplete_switch_case_addrs: set[int] = set()

        # node_order keeps a dictionary of nodes and their order in a quasi-topological sort of the region full graph
        # (graph_with_successors). _generate_node_order() initializes this dictionary. we then update this dictionary
        # when new nodes are created. we do not populate this dictionary when working on acyclic graphs because it's
        # not used for acyclic graphs.
        self._node_order: dict[Any, int] | None = None

        self._use_multistmtexprs = use_multistmtexprs
        self._multistmtexpr_stmt_threshold = multistmtexpr_stmt_threshold
        self._analyze()

    @staticmethod
    def _assert_graph_ok(g, msg: str) -> None:
        if _DEBUG:
            if g is None:
                return
            assert (
                len(list(networkx.connected_components(networkx.Graph(g)))) <= 1
            ), f"{msg}: More than one connected component. Please report this."
            assert (
                len([nn for nn in g if g.in_degree[nn] == 0]) <= 1
            ), f"{msg}: More than one graph entrance. Please report this."

    def _analyze(self):
        # iterate until there is only one node in the region

        self._assert_graph_ok(self._region.graph, "Incorrect region graph")

        has_cycle = self._has_cycle()

        # special handling for single-node loops
        if len(self._region.graph.nodes) == 1 and has_cycle:
            self._analyze_cyclic()

        # backup the region prior to conducting a cyclic refinement because we may not be able to structure a cycle out
        # of the refined graph. in that case, we restore the original region and return.
        pre_refinement_region = None

        while len(self._region.graph.nodes) > 1:
            progressed = self._analyze_acyclic()
            if progressed and self._region.head not in self._region.graph:
                # update the head
                self._region.head = next(
                    iter(node for node in self._region.graph.nodes if node.addr == self._region.head.addr)
                )

            if has_cycle:
                progressed |= self._analyze_cyclic()
                if progressed:
                    pre_refinement_region = None
                    if self._region.head not in self._region.graph:
                        # update the loop head
                        self._region.head = next(
                            iter(node for node in self._region.graph.nodes if node.addr == self._region.head.addr)
                        )
                elif pre_refinement_region is None:
                    pre_refinement_region = self._region.copy()
                    refined = self._refine_cyclic()
                    if refined:
                        if self._region.head not in self._region.graph:
                            # update the loop head
                            self._region.head = next(
                                iter(node for node in self._region.graph.nodes if node.addr == self._region.head.addr)
                            )
                        has_cycle = self._has_cycle()
                        continue
                has_cycle = self._has_cycle()

            if not progressed:
                if self._region.cyclic_ancestor and not self._region.cyclic:
                    # we prefer directly returning this subgraph in case it can be further restructured within a loop
                    # region
                    l.debug("No progress is made on this acyclic graph with a cyclic ancestor. Give up.")
                    break

                l.debug("No progress is made. Enter last resort refinement.")
                removed_edge = self._last_resort_refinement(
                    self._region.head,
                    self._region.graph,
                    (
                        self._region.graph_with_successors
                        if self._region.graph_with_successors is not None
                        else networkx.DiGraph(self._region.graph)
                    ),
                )
                self._assert_graph_ok(self._region.graph, "Last resort refinement went wrong")
                if not removed_edge:
                    # cannot make any progress in this region. return the subgraph directly
                    break

        if len(self._region.graph.nodes) == 1:
            # successfully structured
            self.result = next(iter(self._region.graph.nodes))
        else:
            if pre_refinement_region is not None:
                # we could not make a loop after the last cycle refinement. restore the graph
                l.debug("Could not structure the cyclic graph. Restoring the region to the pre-refinement state.")
                self._region = pre_refinement_region

            self.result = None  # the actual result is in self._region.graph and self._region.graph_with_successors

    def _analyze_cyclic(self) -> bool:
        any_matches = False

        if self._node_order is None:
            self._generate_node_order()
        acyclic_graph = to_acyclic_graph(_f(self._region.graph), node_order=self._node_order)
        for node in list(GraphUtils.dfs_postorder_nodes_deterministic(acyclic_graph, self._region.head)):
            if node not in self._region.graph:
                continue
            matched = self._match_cyclic_schemas(
                node,
                self._region.head,
                self._region.graph,
                (
                    self._region.graph_with_successors
                    if self._region.graph_with_successors is not None
                    else networkx.DiGraph(self._region.graph)
                ),
            )
            l.debug("... matching cyclic schemas: %s at %r", matched, node)
            any_matches |= matched
            if matched:
                self._assert_graph_ok(self._region.graph, "Removed incorrect edges")
        return any_matches

    def _match_cyclic_schemas(self, node, head, graph, full_graph) -> bool:
        matched, loop_node, successor_node = self._match_cyclic_while(node, head, graph, full_graph)
        if matched:
            assert loop_node is not None and successor_node is not None
            # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
            self._rewrite_conditional_jumps_to_breaks(loop_node.sequence_node, [successor_node.addr])
            # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
            self._rewrite_jumps_to_continues(loop_node.sequence_node)
            return True

        matched, loop_node, successor_node = self._match_cyclic_dowhile(node, head, graph, full_graph)
        if matched:
            assert loop_node is not None and successor_node is not None
            # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
            self._rewrite_conditional_jumps_to_breaks(loop_node.sequence_node, [successor_node.addr])
            # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
            self._rewrite_jumps_to_continues(loop_node.sequence_node, loop_node=loop_node)
            return True

        if self._improve_algorithm:
            matched, loop_node, successor_node = self._match_cyclic_while_with_single_successor(
                node, head, graph, full_graph
            )
            if matched:
                assert loop_node is not None and successor_node is not None
                # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
                self._rewrite_conditional_jumps_to_breaks(loop_node.sequence_node, [successor_node.addr])
                # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
                self._rewrite_jumps_to_continues(loop_node.sequence_node)
                return True

        matched, loop_node, successor_node = self._match_cyclic_natural_loop(node, head, graph, full_graph)
        if matched:
            assert loop_node is not None
            if successor_node is not None:
                # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
                self._rewrite_conditional_jumps_to_breaks(loop_node.sequence_node, [successor_node.addr])
            elif self._region.successors is not None and len(self._region.successors) == 1:
                # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
                self._rewrite_conditional_jumps_to_breaks(
                    loop_node.sequence_node, [succ.addr for succ in self._region.successors]
                )
            # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
            self._rewrite_jumps_to_continues(loop_node.sequence_node)
        return matched

    def _match_cyclic_while(
        self, node, head, graph_raw, full_graph_raw
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:
        full_graph = _f(full_graph_raw)

        succs = list(full_graph_raw.successors(node))
        if len(succs) == 2:
            left, right = succs

            if full_graph_raw.has_edge(right, node) and not full_graph_raw.has_edge(left, node):
                left, right = right, left
            if left is node:
                # self loop
                # possible candidate
                head_block_idx, _, head_block = self._find_node_going_to_dst(node, left)
                if head_block is None:
                    # it happens. for example:
                    # ## Block 4058c8
                    # 00 | 0x4058c8 | if ((rcx<8> == 0x0<64>)) { Goto 0x4058ca<64> } else { Goto None }
                    # 01 | 0x4058c8 | rcx<8> = (rcx<8> - 0x1<64>)
                    # 02 | 0x4058c8 | cc_dep1<8> = Conv(8->64, Load(addr=rsi<8>, size=1, endness=Iend_LE))
                    # 03 | 0x4058c8 | cc_dep2<8> = Conv(8->64, Load(addr=rdi<8>, size=1, endness=Iend_LE))
                    # 04 | 0x4058c8 | rdi<8> = (rdi<8> + d<8>)
                    # 05 | 0x4058c8 | rsi<8> = (rsi<8> + d<8>)
                    # 06 | 0x4058c8 | if ((Conv(64->8, cc_dep1<8>) == Conv(64->8, cc_dep2<8>))) { Goto 0x4058c8<64> }
                    #   else { Goto None }
                    # 07 | 0x4058c8 | Goto(0x4058ca<64>)
                    head_block_idx, _, head_block = self._find_node_going_to_dst(node, right)

                if (
                    isinstance(head_block, MultiNode)
                    and head_block.nodes
                    and isinstance(head_block.nodes[0], Block)
                    and head_block.nodes[0].statements
                    and is_head_controlled_loop_block(head_block.nodes[0])
                ) or (
                    isinstance(head_block, Block)
                    and head_block.statements
                    and is_head_controlled_loop_block(head_block)
                ):
                    # it's a while loop if the conditional jump (or the head block) is at the beginning of node
                    loop_type = "while" if head_block_idx == 0 else "do-while"
                    # otherwise it's a do-while loop
                    if self.cond_proc.have_opposite_edge_conditions(full_graph_raw, head_block, left, right):
                        # c = !c
                        edge_cond_left = self.cond_proc.recover_edge_condition(full_graph_raw, head_block, left)
                        if head_block_idx == 0:
                            self._remove_first_statement_if_jump(head_block)
                        else:
                            remove_last_statement(head_block)
                        seq_node = SequenceNode(node.addr, nodes=[node]) if not isinstance(node, SequenceNode) else node
                        loop_node = LoopNode(loop_type, edge_cond_left, seq_node, addr=seq_node.addr)
                        self.replace_nodes(graph_raw, node, loop_node, self_loop=False, drop_refinement_marks=True)
                        self.replace_nodes(
                            full_graph_raw,
                            node,
                            loop_node,
                            self_loop=False,
                            update_node_order=True,
                            drop_refinement_marks=True,
                        )

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except(graph_raw, loop_node, right)
                        self._remove_edges_except(full_graph_raw, loop_node, right)

                        return True, loop_node, right
            elif (
                full_graph_raw.has_edge(left, node)
                and left is not head
                and full_graph_raw.in_degree[left] == 1
                and full_graph.out_degree[left] == 1
                and not full_graph_raw.has_edge(right, node)
            ):
                # possible candidate
                _, _, head_block = self._find_node_going_to_dst(node, left, condjump_only=True)
                if head_block is not None:
                    if self.cond_proc.have_opposite_edge_conditions(full_graph_raw, head_block, left, right):
                        # c = !c
                        if PhoenixStructurer._is_single_statement_block(node):
                            # the single-statement-block check is to ensure we don't execute any code before the
                            # conditional jump. this way the entire node can be dropped.
                            edge_cond_left = self.cond_proc.recover_edge_condition(full_graph_raw, head_block, left)
                            new_node = SequenceNode(node.addr, nodes=[left])
                            loop_node = LoopNode("while", edge_cond_left, new_node, addr=node.addr)

                            # on the original graph
                            self.replace_nodes(
                                graph_raw, node, loop_node, old_node_1=left, self_loop=False, drop_refinement_marks=True
                            )
                            # on the graph with successors
                            self.replace_nodes(
                                full_graph_raw,
                                node,
                                loop_node,
                                old_node_1=left,
                                self_loop=False,
                                update_node_order=True,
                            )

                            # ensure the loop has only one successor: the right node
                            self._remove_edges_except(graph_raw, loop_node, right)
                            self._remove_edges_except(full_graph_raw, loop_node, right)

                            return True, loop_node, right
                        # we generate a while-true loop instead
                        edge_cond_right = self.cond_proc.recover_edge_condition(full_graph_raw, head_block, right)
                        last_stmt = self._remove_last_statement_if_jump(head_block)
                        assert last_stmt is not None
                        cond_jump = Jump(
                            None,
                            Const(None, None, right.addr, self.project.arch.bits),
                            None,
                            ins_addr=last_stmt.ins_addr,
                        )
                        jump_node = Block(last_stmt.ins_addr, None, statements=[cond_jump])
                        cond_jump_node = ConditionNode(last_stmt.ins_addr, None, edge_cond_right, jump_node)
                        new_node = SequenceNode(node.addr, nodes=[node, cond_jump_node, left])
                        loop_node = LoopNode("while", claripy.true(), new_node, addr=node.addr)

                        # on the original graph
                        self.replace_nodes(
                            graph_raw, node, loop_node, old_node_1=left, self_loop=False, drop_refinement_marks=True
                        )
                        # on the graph with successors
                        self.replace_nodes(
                            full_graph_raw,
                            node,
                            loop_node,
                            old_node_1=left,
                            self_loop=False,
                            update_node_order=True,
                            drop_refinement_marks=True,
                        )

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except(graph_raw, loop_node, right)
                        self._remove_edges_except(full_graph_raw, loop_node, right)

                        return True, loop_node, right

                if self._improve_algorithm and full_graph.out_degree[node] == 1:
                    # while (true) { ...; if (...) break; }
                    _, _, head_block = self._find_node_going_to_dst(node, left, condjump_only=True)
                    if head_block is not None:
                        if self.cond_proc.have_opposite_edge_conditions(full_graph, head_block, left, right):
                            # c = !c
                            edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, head_block, right)
                            self._remove_last_statement_if_jump(head_block)
                            cond_break = ConditionalBreakNode(node.addr, edge_cond_right, right.addr)
                            new_node = SequenceNode(node.addr, nodes=[node, cond_break, left])
                            loop_node = LoopNode("while", claripy.true(), new_node, addr=node.addr)

                            # on the original graph
                            self.replace_nodes(
                                graph_raw, node, loop_node, old_node_1=left, self_loop=False, drop_refinement_marks=True
                            )
                            # on the graph with successors
                            self.replace_nodes(
                                full_graph_raw,
                                node,
                                loop_node,
                                old_node_1=left,
                                self_loop=False,
                                update_node_order=True,
                                drop_refinement_marks=True,
                            )

                            # ensure the loop has only one successor: the right node
                            self._remove_edges_except(graph_raw, loop_node, right)
                            self._remove_edges_except(full_graph_raw, loop_node, right)

                            return True, loop_node, right

        return False, None, None

    def _match_cyclic_while_with_single_successor(
        self, node, head, graph_raw, full_graph_raw
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:
        if self._region.successors:
            return False, None, None
        if node is not head:
            return False, None, None

        full_graph = full_graph_raw
        graph = graph_raw

        if not (node is head or graph.in_degree[node] == 2):
            return False, None, None

        loop_cond = None
        successor_node = None
        succ_node_is_true_node = None
        if (
            isinstance(node, SequenceNode)
            and node.nodes
            and isinstance(node.nodes[-1], ConditionNode)
            # must ensure the nodes before the condition node are empty. otherwise the condition may use variables that
            # are updated in these nodes leading up to the condition node.
            and all(not self.has_nonlabel_nonphi_statements(nn) for nn in node.nodes[:-1])
            and node.nodes[-1].true_node is not None
            and node.nodes[-1].false_node is not None
        ):
            # try both true node and false node; pick the first node with only Returns as last statements as the
            # successor.
            if self._cyclic_while_with_single_successor_must_return(node.nodes[-1].true_node):
                succ_node_is_true_node = True
                successor_node = node.nodes[-1].true_node
                loop_cond = claripy.Not(node.nodes[-1].condition)
            elif self._cyclic_while_with_single_successor_must_return(node.nodes[-1].false_node):
                succ_node_is_true_node = False
                successor_node = node.nodes[-1].false_node
                loop_cond = node.nodes[-1].condition
            else:
                loop_cond = None

        if loop_cond is None:
            return False, None, None

        node_copy = node.copy()
        # replace the last node with the intended successor node
        node_copy.nodes[-1] = (
            node_copy.nodes[-1].false_node if succ_node_is_true_node else node_copy.nodes[-1].true_node
        )
        # check if there is a cycle that starts with node and ends with node
        next_node = node
        seq_node = SequenceNode(node.addr, nodes=[node_copy])
        seen_nodes = set()
        while True:
            succs = list(full_graph.successors(next_node))
            if len(succs) != 1:
                return False, None, None
            next_node = succs[0]

            if next_node is node:
                break
            if next_node is not node and next_node in seen_nodes:
                return False, None, None

            seen_nodes.add(next_node)
            seq_node.nodes.append(next_node)

        loop_node = LoopNode("while", loop_cond, seq_node, addr=node.addr)

        # on the original graph
        for node_ in seq_node.nodes:
            if node_ is not node_copy:
                graph_raw.remove_node(node_)
        self.replace_nodes(graph_raw, node, loop_node, self_loop=False, drop_refinement_marks=True)
        graph_raw.add_edge(loop_node, successor_node)

        # on the graph with successors
        for node_ in seq_node.nodes:
            if node_ is not node_copy:
                full_graph_raw.remove_node(node_)
        self.replace_nodes(
            full_graph_raw, node, loop_node, self_loop=False, update_node_order=True, drop_refinement_marks=True
        )
        full_graph_raw.add_edge(loop_node, successor_node)

        if self._node_order is not None:
            self._node_order[loop_node] = self._node_order[node]
            self._node_order[successor_node] = self._node_order[loop_node]

        return True, loop_node, successor_node

    def _cyclic_while_with_single_successor_must_return(self, successor_node: SequenceNode) -> bool:
        try:
            last_stmts = self.cond_proc.get_last_statements(successor_node)
        except EmptyBlockNotice:
            return False
        if not last_stmts:
            return False
        return all(isinstance(stmt, Return) for stmt in last_stmts)

    def _match_cyclic_dowhile(
        self, node, head, graph_raw, full_graph_raw
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:
        full_graph = _f(full_graph_raw)

        preds_raw = list(full_graph_raw.predecessors(node))
        succs_raw = list(full_graph_raw.successors(node))
        succs = list(full_graph.successors(node))

        if ((node is head and len(preds_raw) >= 1) or len(preds_raw) >= 2) and len(succs) == 1:
            succ = succs[0]
            succ_preds = list(full_graph.predecessors(succ))
            succ_succs = list(full_graph.successors(succ))
            if head is not succ and len(succ_succs) == 2 and node in succ_succs and len(succ_preds) == 1:
                succ_succs.remove(node)
                out_node = succ_succs[0]

                if (len(succs_raw) == 1 or (len(succs_raw) == 2 and out_node in succs_raw)) and full_graph.has_edge(
                    succ, node
                ):
                    # possible candidate
                    _, _, succ_block = self._find_node_going_to_dst(succ, out_node, condjump_only=True)
                    if succ_block is not None:
                        if self.cond_proc.have_opposite_edge_conditions(full_graph, succ_block, node, out_node):
                            # c = !c
                            edge_cond_succhead = self.cond_proc.recover_edge_condition(full_graph, succ_block, node)
                            self._remove_last_statement_if_jump(succ)
                            drop_succ = False

                            # absorb the entire succ block if possible
                            if (
                                self._improve_algorithm
                                and self._is_sequential_statement_block(succ)
                                and self._should_use_multistmtexprs(succ)
                            ):
                                stmts = self._build_multistatementexpr_statements(succ)
                                assert stmts is not None
                                if (
                                    stmts
                                    and sum(1 for stmt in stmts if not isinstance(stmt, Label))
                                    <= self._multistmtexpr_stmt_threshold
                                ):
                                    edge_cond_succhead = MultiStatementExpression(
                                        None,
                                        stmts,
                                        self.cond_proc.convert_claripy_bool_ast(edge_cond_succhead),
                                        ins_addr=succ.addr,
                                    )
                                drop_succ = True

                            new_node = SequenceNode(node.addr, nodes=[node] if drop_succ else [node, succ])
                            loop_node = LoopNode("do-while", edge_cond_succhead, new_node, addr=node.addr)

                            # on the original graph
                            self.replace_nodes(
                                graph_raw, node, loop_node, old_node_1=succ, self_loop=False, drop_refinement_marks=True
                            )
                            # on the graph with successors
                            self.replace_nodes(
                                full_graph_raw,
                                node,
                                loop_node,
                                old_node_1=succ,
                                self_loop=False,
                                update_node_order=True,
                                drop_refinement_marks=True,
                            )

                            return True, loop_node, out_node
        elif ((node is head and len(preds_raw) >= 1) or len(preds_raw) >= 2) and len(succs) == 2 and node in succs:
            # head forms a self-loop
            succs.remove(node)
            succ = succs[0]
            if not full_graph.has_edge(succ, node):
                # possible candidate
                if self.cond_proc.have_opposite_edge_conditions(full_graph, node, node, succ):
                    # c = !c
                    edge_cond_head = self.cond_proc.recover_edge_condition(full_graph, node, node)
                    self._remove_last_statement_if_jump(node)
                    seq_node = SequenceNode(node.addr, nodes=[node]) if not isinstance(node, SequenceNode) else node
                    loop_node = LoopNode("do-while", edge_cond_head, seq_node, addr=seq_node.addr)

                    # on the original graph
                    self.replace_nodes(graph_raw, node, loop_node, self_loop=False, drop_refinement_marks=True)
                    # on the graph with successors
                    self.replace_nodes(
                        full_graph_raw,
                        node,
                        loop_node,
                        self_loop=False,
                        update_node_order=True,
                        drop_refinement_marks=True,
                    )

                    return True, loop_node, succ
        return False, None, None

    def _match_cyclic_natural_loop(
        self, node, head, graph_raw, full_graph_raw
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:

        full_graph = _f(full_graph_raw)
        graph = _f(graph_raw)

        if not (node is head or graph.in_degree[node] == 2):
            return False, None, None

        # check if there is a cycle that starts with node and ends with node
        next_node = node
        seq_node = SequenceNode(node.addr, nodes=[node])
        seen_nodes = set()
        loop_successor_candidates = set()
        while True:
            succs = list(full_graph.successors(next_node))
            if len(succs) != 1:
                return False, None, None
            if full_graph.out_degree[next_node] > 1:
                # all successors in the full graph should have been refined away at this point
                return False, None, None

            if full_graph_raw.out_degree[next_node] > 1:
                for _, raw_succ, edge_data in full_graph_raw.out_edges(next_node, data=True):
                    if raw_succ is succs[0]:
                        continue
                    if edge_data.get("cyclic_refinement_outgoing", False) is True:
                        loop_successor_candidates.add(raw_succ)
                    else:
                        # bad node found
                        return False, None, None

            next_node = succs[0]

            if next_node is node:
                break
            if next_node is head:
                # we don't want a loop with region head not as the first node of the body!
                return False, None, None
            if next_node is not node and next_node in seen_nodes:
                return False, None, None

            seen_nodes.add(next_node)
            seq_node.nodes.append(next_node)

        if len(loop_successor_candidates) > 1:
            return False, None, None

        loop_node = LoopNode("while", claripy.true(), seq_node, addr=node.addr)

        # on the original graph
        for node_ in seq_node.nodes:
            if node_ is not node:
                graph_raw.remove_node(node_)
        self.replace_nodes(graph_raw, node, loop_node, self_loop=False, drop_refinement_marks=True)

        # on the graph with successors
        for node_ in seq_node.nodes:
            if node_ is not node:
                full_graph_raw.remove_node(node_)
        self.replace_nodes(
            full_graph_raw, node, loop_node, self_loop=False, update_node_order=True, drop_refinement_marks=True
        )

        successor = None if not loop_successor_candidates else next(iter(loop_successor_candidates))
        if successor is not None:
            if successor in graph:
                graph_raw.add_edge(loop_node, successor)
            if successor in full_graph:
                full_graph_raw.add_edge(loop_node, successor)

        return True, loop_node, successor

    def _refine_cyclic(self) -> bool:
        graph = _f(self._region.graph)
        loop_heads = {t for _, t in dfs_back_edges(graph, self._region.head, visit_all_nodes=True)}
        sorted_loop_heads = GraphUtils.quasi_topological_sort_nodes(graph, nodes=list(loop_heads))

        for head in sorted_loop_heads:
            l.debug("... refining cyclic at %r", head)
            refined = self._refine_cyclic_core(head)
            l.debug("... refined: %s", refined)
            if refined:
                self._assert_graph_ok(self._region.graph, "Refinement went wrong")
                # cyclic refinement may create dangling nodes in the full graph
                return True
        return False

    def _refine_cyclic_core(self, loop_head) -> bool:
        graph_raw: networkx.DiGraph = self._region.graph
        fullgraph_raw: networkx.DiGraph = (
            self._region.graph_with_successors
            if self._region.graph_with_successors is not None
            else networkx.DiGraph(self._region.graph)
        )

        graph = _f(graph_raw)
        fullgraph = _f(fullgraph_raw)

        # check if there is an out-going edge from the loop head
        head_succs = list(fullgraph.successors(loop_head))
        successor = None  # the loop successor
        loop_type = None
        # continue_node either the loop header for while(true) loops or the loop header predecessor for do-while loops
        continue_node = loop_head

        is_while, result_while = self._refine_cyclic_is_while_loop(graph, fullgraph, loop_head, head_succs)
        is_dowhile, result_dowhile = self._refine_cyclic_is_dowhile_loop(graph, fullgraph, loop_head)

        continue_edges: list[tuple[BaseNode, BaseNode]] = []
        outgoing_edges: list = []

        # gotta pick one!
        # for now, we handle the most common case: both successors exist in the graph of the parent region, and
        # one successor has a path to the other successor
        if is_while and is_dowhile and self._parent_region is not None:
            assert result_while is not None and result_dowhile is not None
            succ_while = result_while[-1]
            succ_dowhile = result_dowhile[-1]
            if succ_while in self._parent_region.graph and succ_dowhile in self._parent_region.graph:
                sorted_nodes = GraphUtils.quasi_topological_sort_nodes(
                    self._parent_region.graph, loop_heads=[self._parent_region.head]
                )
                succ_while_idx = sorted_nodes.index(succ_while)
                succ_dowhile_idx = sorted_nodes.index(succ_dowhile)
                if succ_dowhile_idx < succ_while_idx:
                    # pick do-while
                    is_while = False

        if is_while:
            assert result_while is not None
            loop_type = "while"
            continue_edges, outgoing_edges, continue_node, successor = result_while
        elif is_dowhile:
            assert result_dowhile is not None
            loop_type = "do-while"
            continue_edges, outgoing_edges, continue_node, successor = result_dowhile

        if loop_type is None:
            # natural loop. select *any* exit edge to determine the successor
            is_natural, result_natural = self._refine_cyclic_make_natural_loop(graph, fullgraph, loop_head)
            if not is_natural:
                # cannot refine this loop
                return False
            assert result_natural is not None
            continue_edges, outgoing_edges, successor = result_natural

        if outgoing_edges:
            # if there is a single successor, we convert all but the first one out-going edges into breaks;
            # if there are multiple successors, and if the current region does not have a parent region, then we
            # convert all but the first successor-targeting out-going edges into gotos;
            # otherwise we give up.

            if self._parent_region is not None and len({dst for _, dst in outgoing_edges}) > 1:
                # give up because there is a parent region
                return False

            # sanity check: if removing outgoing edges would create dangling nodes, then it means we are not ready for
            # cyclic refinement yet.
            outgoing_edges_by_dst = defaultdict(list)
            for src, dst in outgoing_edges:
                outgoing_edges_by_dst[dst].append(src)
            for dst, srcs in outgoing_edges_by_dst.items():
                if dst in graph and graph.in_degree[dst] == len(srcs):
                    return False

            outgoing_edges = sorted(outgoing_edges, key=lambda edge: (edge[0].addr, edge[1].addr))

            if successor is None:
                successor_and_edgecounts = defaultdict(int)
                for _, dst in outgoing_edges:
                    successor_and_edgecounts[dst] += 1

                if len(successor_and_edgecounts) > 1:
                    # pick one successor with the highest edge count and (in case there are multiple successors with the
                    # same edge count) the lowest address
                    max_edgecount = max(successor_and_edgecounts.values())
                    successor_candidates = [
                        nn for nn, edgecount in successor_and_edgecounts.items() if edgecount == max_edgecount
                    ]
                    successor = next(iter(sorted(successor_candidates, key=lambda x: x.addr)))
                else:
                    successor = next(iter(successor_and_edgecounts.keys()))

            for src, dst in outgoing_edges:
                if dst is successor:
                    # keep in mind that at this point, src might have been structured already. this means the last
                    # block in src may not be the actual block that has a direct jump or a conditional jump to dst. as
                    # a result, we should walk all blocks in src to find the jump to dst, then extract the condition
                    # and augment the corresponding block with a ConditionalBreak.
                    _, _, src_block = self._find_node_going_to_dst(src, dst)
                    if src_block is None:
                        l.warning(
                            "Cannot find the source block jumping to the destination block at %#x. "
                            "This is likely a bug elsewhere and needs to be addressed.",
                            dst.addr,
                        )
                        # remove the edge anyway
                        fullgraph_raw[src][dst]["cyclic_refinement_outgoing"] = True
                        if graph.has_edge(src, dst):
                            graph_raw[src][dst]["cyclic_refinement_outgoing"] = True
                    elif not isinstance(src_block, (Block, MultiNode)):
                        # it has probably been structured into BreakNode or ConditionalBreakNode
                        # just remove the edge
                        fullgraph_raw[src][dst]["cyclic_refinement_outgoing"] = True
                        if graph.has_edge(src, dst):
                            graph_raw[src][dst]["cyclic_refinement_outgoing"] = True
                    else:
                        has_continue = False
                        # at the same time, examine if there is an edge that goes from src to the continue node. if so,
                        # we deal with it here as well.
                        continue_node_going_edge = src, continue_node
                        if continue_node_going_edge in continue_edges:
                            has_continue = True
                            # do not remove the edge from continue_edges since we want to process them later in this
                            # function.

                        # create the "break" node. in fact, we create a jump or a conditional jump, which will be
                        # rewritten to break nodes after (if possible). directly creating break nodes may lead to
                        # unwanted results, e.g., inserting a break (that's intended to break out of the loop) inside a
                        # switch-case that is nested within a loop.
                        last_src_stmt = self.cond_proc.get_last_statement(src_block)
                        assert last_src_stmt is not None
                        break_cond = self.cond_proc.recover_edge_condition(fullgraph, src_block, dst)
                        assert successor.addr is not None
                        if claripy.is_true(break_cond):
                            break_stmt = Jump(
                                None,
                                Const(None, None, successor.addr, self.project.arch.bits),
                                target_idx=successor.idx if isinstance(successor, Block) else None,
                                ins_addr=last_src_stmt.ins_addr,
                            )
                            break_node = Block(last_src_stmt.ins_addr, None, statements=[break_stmt])
                        else:
                            break_stmt = Jump(
                                None,
                                Const(None, None, successor.addr, self.project.arch.bits),
                                target_idx=successor.idx if isinstance(successor, Block) else None,
                                ins_addr=last_src_stmt.ins_addr,
                            )
                            break_node_inner = Block(last_src_stmt.ins_addr, None, statements=[break_stmt])
                            fallthrough_node = next(iter(succ for succ in fullgraph.successors(src) if succ is not dst))
                            fallthrough_stmt = Jump(
                                None,
                                Const(None, None, fallthrough_node.addr, self.project.arch.bits),
                                target_idx=successor.idx if isinstance(successor, Block) else None,
                                ins_addr=last_src_stmt.ins_addr,
                            )
                            break_node_inner_fallthrough = Block(
                                last_src_stmt.ins_addr, None, statements=[fallthrough_stmt]
                            )
                            break_node = ConditionNode(
                                last_src_stmt.ins_addr,
                                None,
                                break_cond,
                                break_node_inner,
                                false_node=break_node_inner_fallthrough,
                            )
                        new_src_block = self._copy_and_remove_last_statement_if_jump(src_block)
                        new_node = SequenceNode(src_block.addr, nodes=[new_src_block, break_node])
                        if has_continue:
                            assert continue_node is not None

                            if continue_node.addr is not None and self.is_a_jump_target(
                                last_src_stmt, continue_node.addr
                            ):
                                # instead of a conditional break node, we should insert a condition node instead
                                break_stmt = Jump(
                                    None,
                                    Const(None, None, successor.addr, self.project.arch.bits),
                                    target_idx=successor.idx if isinstance(successor, Block) else None,
                                    ins_addr=last_src_stmt.ins_addr,
                                )
                                break_node = Block(last_src_stmt.ins_addr, None, statements=[break_stmt])
                                cont_node = ContinueNode(
                                    last_src_stmt.ins_addr,
                                    Const(None, None, continue_node.addr, self.project.arch.bits),
                                )
                                cond_node = ConditionNode(
                                    last_src_stmt.ins_addr,
                                    None,
                                    break_cond,
                                    break_node,
                                )
                                new_node.nodes[-1] = cond_node
                                new_node.nodes.append(cont_node)

                                # we don't remove the edge (src, continue_node) from the graph or full graph. we will
                                # process them later in this function.
                            else:
                                # the last statement in src_block is not the conditional jump whose one branch goes to
                                # the loop head. it probably goes to another block that ends up going to the loop head.
                                # we don't handle it here.
                                pass

                        # we cannot modify the original src_block because loop refinement may fail and we must restore
                        # the original graph
                        new_src = NodeReplacer(src, {src_block: new_node}).result
                        if graph.has_edge(src, dst):
                            graph_raw[src][dst]["cyclic_refinement_outgoing"] = True
                        self.replace_nodes(graph_raw, src, new_src)
                        fullgraph_raw[src][dst]["cyclic_refinement_outgoing"] = True
                        self.replace_nodes(fullgraph_raw, src, new_src, update_node_order=True)
                        if src is loop_head:
                            loop_head = new_src
                        if src is continue_node:
                            continue_node = new_src

                        self._replace_node_in_edge_list(outgoing_edges, src, new_src)
                        self._replace_node_in_edge_list(continue_edges, src, new_src)

                else:
                    self.virtualized_edges.add((src, dst))
                    fullgraph_raw.remove_edge(src, dst)
                    if graph.has_edge(src, dst):
                        graph_raw.remove_edge(src, dst)
                    if fullgraph.in_degree[dst] == 0:
                        # drop this node
                        fullgraph_raw.remove_node(dst)
                        if self._region.successors and dst in self._region.successors:
                            self._region.successors.remove(dst)

        if len(continue_edges) > 1:
            # convert all but one (the one that is the farthest from the head, topological-wise) head-going edges into
            # continues
            sorted_nodes = GraphUtils.quasi_topological_sort_nodes(
                fullgraph, nodes=[src for src, _ in continue_edges], loop_heads=[loop_head]
            )
            src_to_ignore = sorted_nodes[-1]

            for src, _ in continue_edges:
                if src is src_to_ignore:
                    # this edge will be handled during loop structuring
                    # mark it regardless
                    continue

                # due to prior structuring of sub regions, the continue node may already be a Jump statement deep in
                # src at this point. we need to find the Jump statement and replace it.
                assert continue_node is not None
                _, _, cont_block = self._find_node_going_to_dst(src, continue_node)
                if cont_block is None:
                    # cont_block is not found. but it's ok. one possibility is that src is a jump table head with one
                    # case being the loop head. in such cases, we can just remove the edge.
                    if src.addr not in self.jump_tables:
                        l.debug(
                            "_refine_cyclic_core: Cannot find the block going to loop head for edge %r -> %r. "
                            "Remove the edge anyway.",
                            src,
                            continue_node,
                        )
                    if graph.has_edge(src, continue_node):
                        graph_raw.remove_edge(src, continue_node)
                    fullgraph_raw.remove_edge(src, continue_node)
                else:
                    # remove the edge.
                    graph_raw.remove_edge(src, continue_node)
                    fullgraph_raw.remove_edge(src, continue_node)
                    # replace it with the original node plus the continue node
                    try:
                        last_stmt = self.cond_proc.get_last_statement(cont_block)
                    except EmptyBlockNotice:
                        # meh
                        last_stmt = None
                    if last_stmt is not None:
                        new_cont_node = None
                        if isinstance(last_stmt, ConditionalJump):
                            new_cont_node = ContinueNode(last_stmt.ins_addr, continue_node.addr)
                            if (
                                isinstance(last_stmt.true_target, Const)
                                and last_stmt.true_target.value == continue_node.addr
                            ):
                                new_cont_node = ConditionNode(
                                    last_stmt.ins_addr, None, last_stmt.condition, new_cont_node
                                )
                            else:
                                new_cont_node = ConditionNode(
                                    last_stmt.ins_addr,
                                    None,
                                    UnaryOp(None, "Not", last_stmt.condition),
                                    new_cont_node,
                                )
                        elif isinstance(last_stmt, Jump):
                            new_cont_node = ContinueNode(last_stmt.ins_addr, continue_node.addr)

                        if new_cont_node is not None and isinstance(cont_block, (Block, MultiNode)):
                            new_cont_block = self._copy_and_remove_last_statement_if_jump(cont_block)
                            new_node = NodeReplacer(src, {cont_block: new_cont_block}).result
                            new_src = SequenceNode(new_node.addr, nodes=[new_node, new_cont_node])
                            self.replace_nodes(graph_raw, src, new_src)
                            self.replace_nodes(fullgraph_raw, src, new_src, update_node_order=True)

        if loop_type == "do-while":
            self.dowhile_known_tail_nodes.add(continue_node)

        return bool(outgoing_edges or len(continue_edges) > 1)

    @staticmethod
    def _refine_cyclic_determine_loop_body(graph, fullgraph, loop_head, successor=None) -> set[BaseNode]:
        # determine the loop body: all nodes that have paths going to loop_head
        loop_body = {loop_head}
        for node in networkx.descendants(fullgraph, loop_head):
            if node in graph and networkx.has_path(graph, node, loop_head):
                loop_body.add(node)

        # extend the loop body if possible
        while True:
            loop_body_updated = False
            for node in list(loop_body):
                new_nodes = set()
                succ_not_in_loop_body = False
                for succ in fullgraph.successors(node):
                    if successor is not None and succ is successor:
                        continue
                    if succ not in loop_body and succ in graph and fullgraph.out_degree[succ] <= 1:
                        if all(pred in loop_body for pred in fullgraph.predecessors(succ)):
                            new_nodes.add(succ)
                        else:
                            # one of the predecessors of this successor is not in the loop body
                            succ_not_in_loop_body = True
                if new_nodes and not succ_not_in_loop_body:
                    loop_body |= new_nodes
                    loop_body_updated = True
            if not loop_body_updated:
                break

        return loop_body

    @staticmethod
    def _refine_cyclic_is_while_loop_check_loop_head_successors(graph, head_succs) -> tuple[bool, Any]:
        assert len(head_succs) == 2
        a, b = head_succs
        a_in_graph = a in graph
        b_in_graph = b in graph
        if a_in_graph ^ b_in_graph:
            return True, b if a_in_graph else a
        return False, None

    def _refine_cyclic_is_while_loop(
        self, graph, fullgraph, loop_head, head_succs
    ) -> tuple[bool, tuple[list, list, BaseNode, BaseNode] | None]:
        if len(head_succs) == 2:
            r, successor = self._refine_cyclic_is_while_loop_check_loop_head_successors(graph, head_succs)
            if r:
                # make sure the head_pred is not already structured
                _, _, head_block_0 = self._find_node_going_to_dst(loop_head, head_succs[0])
                _, _, head_block_1 = self._find_node_going_to_dst(loop_head, head_succs[1])
                if head_block_0 is head_block_1 and head_block_0 is not None:
                    # there is an out-going edge from the loop head
                    # virtualize all other edges
                    continue_edges: list[tuple[BaseNode, BaseNode]] = []
                    outgoing_edges = []
                    # note that because we have determined that the loop is a while loop, outgoing_edges do not contain
                    # edges that go from the loop head to the successor.
                    for node in list(networkx.descendants(graph, loop_head)):
                        succs = list(fullgraph.successors(node))
                        if loop_head in succs:
                            continue_edges.append((node, loop_head))
                        outside_succs = [succ for succ in succs if succ not in graph]
                        for outside_succ in outside_succs:
                            outgoing_edges.append((node, outside_succ))
                    return True, (continue_edges, outgoing_edges, loop_head, successor)
        return False, None

    def _refine_cyclic_is_dowhile_loop(
        self, graph, fullgraph, loop_head
    ) -> tuple[bool, tuple[list, list, BaseNode, BaseNode] | None]:
        # check if there is an out-going edge from the loop tail
        head_preds = list(fullgraph.predecessors(loop_head))
        if len(head_preds) == 1:
            head_pred = head_preds[0]
            head_pred_succs = list(fullgraph.successors(head_pred))
            if len(head_pred_succs) == 2:
                successor = next(iter(nn for nn in head_pred_succs if nn is not loop_head))
                # make sure the head_pred is not already structured
                _, _, src_block_0 = self._find_node_going_to_dst(head_pred, loop_head)
                _, _, src_block_1 = self._find_node_going_to_dst(head_pred, successor)
                if src_block_0 is src_block_1 and src_block_0 is not None:
                    continue_edges: list[tuple[BaseNode, BaseNode]] = []
                    outgoing_edges = []
                    # there is an out-going edge from the loop tail
                    # virtualize all other edges
                    continue_node = head_pred
                    loop_body = PhoenixStructurer._refine_cyclic_determine_loop_body(
                        graph, fullgraph, loop_head, successor=successor
                    )
                    for node in loop_body:
                        if node is head_pred:
                            continue
                        succs = list(fullgraph.successors(node))
                        if head_pred in succs:
                            continue_edges.append((node, head_pred))

                        outside_succs = [succ for succ in succs if succ not in loop_body]
                        for outside_succ in outside_succs:
                            outgoing_edges.append((node, outside_succ))

                    return True, (continue_edges, outgoing_edges, continue_node, successor)
        return False, None

    @staticmethod
    def _refine_cyclic_make_natural_loop(graph, fullgraph, loop_head) -> tuple[bool, tuple[list, list, Any] | None]:
        continue_edges = []
        outgoing_edges = []

        loop_body = PhoenixStructurer._refine_cyclic_determine_loop_body(graph, fullgraph, loop_head)

        # determine successor candidates using the loop body
        successor_candidates = set()
        for node in loop_body:
            for succ in fullgraph.successors(node):
                if succ not in loop_body:
                    successor_candidates.add(succ)

        # traverse the loop body to find all continue edges
        for node in loop_body:
            if graph.has_edge(node, loop_head):
                continue_edges.append((node, loop_head))

        if len(successor_candidates) == 0:
            successor = None
        else:
            # one or multiple successors; try to pick a successor in graph, and prioritize the one with the lowest
            # address
            successor_candidates_in_graph = {nn for nn in successor_candidates if nn in graph}
            if successor_candidates_in_graph:
                # pick the one with the lowest address
                successor = next(iter(sorted(successor_candidates_in_graph, key=lambda x: x.addr)))
            else:
                successor = next(iter(sorted(successor_candidates, key=lambda x: x.addr)))
            # mark all edges as outgoing edges so they will be virtualized if they don't lead to the successor
            for node in successor_candidates:
                for pred in fullgraph.predecessors(node):
                    if pred in graph:
                        outgoing_edges.append((pred, node))

        return True, (continue_edges, outgoing_edges, successor)

    def _analyze_acyclic(self) -> bool:
        # match against known schemas
        l.debug("Matching acyclic schemas for region %r.", self._region)

        any_matches = False
        idx = 0
        while True:
            l.debug("_match_acyclic_schemas: Iteration %d", idx)
            idx += 1

            try:
                any_matches_this_iteration = self._match_acyclic_schemas(
                    self._region.graph,
                    (
                        self._region.graph_with_successors
                        if self._region.graph_with_successors is not None
                        else networkx.DiGraph(self._region.graph)
                    ),
                    self._region.head,
                )
            except GraphChangedNotification:
                # restart
                l.debug("_match_acyclic_schemas: Graph changed. Restart.")
                idx = 0
                continue
            if not any_matches_this_iteration:
                break
            any_matches = True

            # update the head if needed
            if self._region.head not in self._region.graph:
                # update the head
                self._region.head = next(
                    iter(node for node in self._region.graph.nodes if node.addr == self._region.head.addr)
                )

        return any_matches

    def _match_acyclic_schemas(self, graph: networkx.DiGraph, full_graph: networkx.DiGraph, head) -> bool:
        # traverse the graph in reverse topological order
        any_matches = False

        self._assert_graph_ok(self._region.graph, "Got a wrong graph to work on")

        if graph.in_degree[head] == 0:
            acyclic_graph = graph
        else:
            acyclic_graph = networkx.DiGraph(graph)
            if len([node for node in acyclic_graph if acyclic_graph.in_degree[node] == 0]) == 0:
                acyclic_graph.remove_edges_from(graph.in_edges(head))
                self._assert_graph_ok(acyclic_graph, "Removed wrong edges")

        for node in list(GraphUtils.dfs_postorder_nodes_deterministic(acyclic_graph, head)):
            if node not in graph:
                continue
            if graph.has_edge(node, head):
                # it's a back edge
                l.debug("... %r -> %r is a back edge", node, head)
                continue
            l.debug("... matching acyclic switch-case constructs at %r", node)
            matched = self._match_acyclic_switch_cases(graph, full_graph, node)
            l.debug("... matched: %s", matched)
            any_matches |= matched
            if matched:
                break
            l.debug("... matching acyclic sequence at %r", node)
            matched = self._match_acyclic_sequence(graph, full_graph, node)
            l.debug("... matched: %s", matched)
            any_matches |= matched
            if matched:
                break
            l.debug("... matching acyclic ITE at %r", node)
            matched = self._match_acyclic_ite(graph, full_graph, node)
            l.debug("... matched: %s", matched)
            any_matches |= matched
            if matched:
                break
            if self._improve_algorithm:
                l.debug("... matching acyclic ITE with short-circuit conditions at %r", node)
                matched = self._match_acyclic_short_circuit_conditions(graph, full_graph, node)
                l.debug("... matched: %s", matched)
                any_matches |= matched
                if matched:
                    break

        self._assert_graph_ok(self._region.graph, "Removed incorrect edges")

        return any_matches

    # switch cases

    def _match_acyclic_switch_cases(self, graph: networkx.DiGraph, full_graph: networkx.DiGraph, node) -> bool:
        if isinstance(node, SwitchCaseNode):
            return False

        r = self._match_acyclic_switch_cases_address_loaded_from_memory_no_default_node(node, graph, full_graph)
        if r:
            return r

        if isinstance(node, IncompleteSwitchCaseNode):
            return False

        r = self._match_acyclic_switch_cases_incomplete_switch_head(node, graph, full_graph)
        if r:
            return r
        r = self._match_acyclic_switch_cases_address_loaded_from_memory_no_ob_check(node, graph, full_graph)
        if r:
            return r
        r = self._match_acyclic_switch_cases_address_loaded_from_memory(node, graph, full_graph)
        if r:
            return r
        r = self._match_acyclic_switch_cases_address_computed(node, graph, full_graph)
        if r:
            return r
        return self._match_acyclic_incomplete_switch_cases(node, graph, full_graph)

    def _match_acyclic_switch_cases_incomplete_switch_head(
        self, node, graph_raw: networkx.DiGraph, full_graph_raw: networkx.DiGraph
    ) -> bool:
        try:
            last_stmts = self.cond_proc.get_last_statements(node)
        except EmptyBlockNotice:
            return False

        if len(last_stmts) != 1:
            return False
        last_stmt = last_stmts[0]
        if not isinstance(last_stmt, IncompleteSwitchCaseHeadStatement):
            return False

        # make a fake jumptable
        node_default_addr = None
        case_entries: dict[int, int | tuple[int, int | None]] = {}
        for _, case_value, case_target_addr, case_target_idx, _ in last_stmt.case_addrs:
            if isinstance(case_value, str):
                if case_value == "default":
                    node_default_addr = case_target_addr
                    continue
                raise ValueError(f"Unsupported 'case_value' {case_value}")
            case_entries[case_value] = (case_target_addr, case_target_idx)

        cases, node_default, to_remove = self._switch_build_cases(
            case_entries,
            node,
            node,
            node_default_addr,
            graph_raw,
            full_graph_raw,
        )
        if node_default_addr is not None and node_default is None:
            # the default node is not found. it's likely the node has been structured and is part of another construct
            # (e.g., inside another switch-case). we need to create a default node that jumps to the other node
            jmp_to_default_node = Jump(
                None,
                Const(None, None, node_default_addr, self.project.arch.bits),
                None,
                ins_addr=SWITCH_MISSING_DEFAULT_NODE_ADDR,
            )
            node_default = Block(SWITCH_MISSING_DEFAULT_NODE_ADDR, 0, statements=[jmp_to_default_node])
            graph_raw.add_edge(node, node_default)
            full_graph_raw.add_edge(node, node_default)
            if self._node_order is not None:
                self._node_order[node_default] = self._node_order[node]
        r = self._make_switch_cases_core(
            node,
            self.cond_proc.claripy_ast_from_ail_condition(last_stmt.switch_variable),
            cases,
            node_default_addr,
            node_default,
            last_stmt.ins_addr,
            to_remove,
            graph_raw,
            full_graph_raw,
            bail_on_nonhead_outedges=True,
        )
        if not r:
            return False

        # special handling of duplicated default nodes
        if node_default is not None and self._region.graph.out_degree[node] > 1:
            other_out_nodes = list(self._region.graph.successors(node))
            for o in other_out_nodes:
                if o.addr == node_default.addr and o is not node_default:
                    self._region.graph.remove_node(o)
                    if self._region.graph_with_successors is not None:
                        self._region.graph_with_successors.remove_node(o)

        switch_end_addr = self._switch_find_switch_end_addr(cases, node_default, {nn.addr for nn in self._region.graph})
        if switch_end_addr is not None:
            self._switch_handle_gotos(cases, node_default, switch_end_addr)
        return True

    def _match_acyclic_switch_cases_address_loaded_from_memory(self, node, graph_raw, full_graph_raw) -> bool:

        successor_addrs: list[int] = []
        cmp_expr: int = 0
        cmp_lb: int = 0
        switch_head_addr: int = 0

        # case 1: the last block is a ConditionNode with two goto statements
        if isinstance(node, SequenceNode) and node.nodes and isinstance(node.nodes[-1], ConditionNode):
            cond_node = node.nodes[-1]
            assert isinstance(cond_node, ConditionNode)
            if (
                cond_node.true_node is not None
                and cond_node.false_node is not None
                and isinstance(cond_node.true_node, Block)
                and isinstance(cond_node.false_node, Block)
            ):
                successor_addrs = [
                    *extract_jump_targets(cond_node.true_node.statements[-1]),
                    *extract_jump_targets(cond_node.false_node.statements[-1]),
                ]
                if len(successor_addrs) != 2 or None in successor_addrs:
                    return False

                # extract the comparison expression, lower-, and upper-bounds from the last statement
                cmp = switch_extract_cmp_bounds_from_condition(
                    self.cond_proc.convert_claripy_bool_ast(cond_node.condition)
                )
                if not cmp:
                    return False
                cmp_expr, cmp_lb, cmp_ub = cmp  # pylint:disable=unused-variable

                assert cond_node.addr is not None
                switch_head_addr = cond_node.addr

        # case 2: the last statement is a conditional jump
        if not successor_addrs:
            try:
                last_stmt = self.cond_proc.get_last_statement(node)
            except EmptyBlockNotice:
                return False

            if last_stmt is None:
                return False

            successor_addrs = extract_jump_targets(last_stmt)
            if len(successor_addrs) != 2:
                return False

            # extract the comparison expression, lower-, and upper-bounds from the last statement
            cmp = switch_extract_cmp_bounds(last_stmt)
            if not cmp:
                return False
            cmp_expr, cmp_lb, cmp_ub = cmp  # pylint:disable=unused-variable

            switch_head_addr = last_stmt.ins_addr

        for t in successor_addrs:
            if t in self.jump_tables:
                # this is a candidate!
                target = t
                break
        else:
            return False

        jump_table = self.jump_tables[target]
        if jump_table.type != IndirectJumpType.Jumptable_AddressLoadedFromMemory:
            return False

        graph = _f(graph_raw)
        full_graph = _f(full_graph_raw)

        node_a = next(iter(nn for nn in graph.nodes if nn.addr == target), None)
        if node_a is None:
            return False
        if node_a is self._region.head:
            # avoid structuring if node_a is the region head; this means the current node is a duplicated switch-case
            # head (instead of the original one), which is not something we want to structure
            return False

        # the default case
        node_b_addr = next(iter(t for t in successor_addrs if t != target), None)
        if node_b_addr is None:
            return False

        # populate whitelist_edges
        assert jump_table.jumptable_entries is not None
        assert isinstance(node_a.addr, int)
        assert isinstance(node.addr, int)
        for case_node_addr in jump_table.jumptable_entries:
            self.whitelist_edges.add((node_a.addr, case_node_addr))
        self.whitelist_edges.add((node.addr, node_b_addr))
        self.whitelist_edges.add((node_a.addr, node_b_addr))
        self.switch_case_known_heads.add(node)

        # sanity check: case nodes are successors to node_a. all case nodes must have at most common one successor
        node_pred = None
        if graph.in_degree[node] == 1:
            node_pred = next(iter(graph.predecessors(node)))

        case_nodes = list(graph.successors(node_a))

        # case 1: the common successor happens to be directly reachable from node_a (usually as a result of compiler
        # optimization)
        # example: touch_touch_no_switch.o:main
        r = self.switch_case_entry_node_has_common_successor_case_1(graph, jump_table, case_nodes, node_pred)

        # case 2: the common successor is not directly reachable from node_a. this is a more common case.
        if not r:
            r |= self.switch_case_entry_node_has_common_successor_case_2(graph, jump_table, case_nodes, node_pred)

        if not r:
            return False

        node_default = self._switch_find_default_node(graph, node, node_b_addr)
        if node_default is not None:
            # ensure we have successfully structured node_default
            if full_graph.out_degree[node_default] > 1:
                return False

        # un-structure IncompleteSwitchCaseNode
        if isinstance(node_a, SequenceNode) and node_a.nodes and isinstance(node_a.nodes[0], IncompleteSwitchCaseNode):
            _, new_seq_node = self._unpack_sequencenode_head(graph_raw, node_a)
            if new_seq_node is not None and self._node_order is not None:
                self._node_order[new_seq_node] = self._node_order[node_a]
            self._unpack_sequencenode_head(full_graph_raw, node_a, new_seq=new_seq_node)
            # update node_a
            node_a = next(iter(nn for nn in graph.nodes if nn.addr == target))
        if isinstance(node_a, IncompleteSwitchCaseNode):
            r = self._unpack_incompleteswitchcasenode(graph_raw, node_a)
            if not r:
                return False
            self._unpack_incompleteswitchcasenode(full_graph_raw, node_a)  # this shall not fail
            # update node_a
            node_a = next(iter(nn for nn in graph.nodes if nn.addr == target))
            if self._node_order is not None:
                self._generate_node_order()

        better_node_a = node_a
        if isinstance(node_a, SequenceNode) and is_empty_or_label_only_node(node_a.nodes[0]) and len(node_a.nodes) == 2:
            better_node_a = node_a.nodes[1]

        case_and_entry_addrs = self._find_case_and_entry_addrs(node_a, graph, cmp_lb, jump_table)

        cases, node_default, to_remove = self._switch_build_cases(
            case_and_entry_addrs,
            node,
            node_a,
            node_b_addr,
            graph_raw,
            full_graph_raw,
        )

        if isinstance(better_node_a, SwitchCaseNode) and better_node_a.default_node is None:
            # we found a different head for an otherwise complete edge case.
            # recreate the switch with it.
            newsc = SwitchCaseNode(better_node_a.switch_expr, better_node_a.cases, node_default, addr=node.addr)

            if node_default is not None and set(graph.succ[node_a]) != set(graph.succ[node_default]):
                # if node_a and default_node have different successors we need to bail
                return False

            for pgraph in (graph_raw, full_graph_raw):
                all_preds = set(pgraph.pred[node])
                all_succs = set(pgraph.succ[node_a])
                if node_default is not None:
                    pgraph.remove_node(node_default)
                pgraph.remove_node(node)
                pgraph.remove_node(node_a)
                pgraph.add_node(newsc)
                for pred in all_preds:
                    pgraph.add_edge(pred, newsc)
                for succ in all_succs:
                    pgraph.add_edge(newsc, succ)

            return True

        if node_default is None:
            switch_end_addr = node_b_addr
        else:
            # we don't know what the end address of this switch-case structure is. let's figure it out
            switch_end_addr = self._switch_find_switch_end_addr(
                cases, node_default, {nn.addr for nn in self._region.graph}
            )
            to_remove.add(node_default)

        to_remove.add(node_a)  # add node_a
        r = self._make_switch_cases_core(
            node,
            cmp_expr,
            cases,
            node_b_addr,
            node_default,
            switch_head_addr,
            to_remove,
            graph_raw,
            full_graph_raw,
            node_a=node_a,
        )
        if not r:
            return False

        # fully structured into a switch-case. remove node from switch_case_known_heads
        self.switch_case_known_heads.remove(node)
        if switch_end_addr is not None:
            self._switch_handle_gotos(cases, node_default, switch_end_addr)

        return True

    def _match_acyclic_switch_cases_address_loaded_from_memory_no_default_node(
        self, node, graph_raw, full_graph_raw
    ) -> bool:
        # sanity checks
        if not isinstance(node, IncompleteSwitchCaseNode):
            return False
        if node.addr not in self.jump_tables:
            return False

        graph = _f(graph_raw)
        full_graph = _f(full_graph_raw)

        # ensure _match_acyclic_switch_cases_address_load_from_memory cannot structure its predecessor (and this node)
        preds = list(graph.predecessors(node))
        if len(preds) != 1:
            return False
        pred = preds[0]
        if full_graph.out_degree[pred] != 1:
            return False
        jump_table: IndirectJump = self.jump_tables[node.addr]
        if jump_table.type != IndirectJumpType.Jumptable_AddressLoadedFromMemory:
            return False

        # extract the comparison expression, lower-, and upper-bounds from the last statement
        last_stmt = self.cond_proc.get_last_statement(node.head)
        if not isinstance(last_stmt, Jump):
            return False
        cmp_expr = switch_extract_switch_expr_from_jump_target(last_stmt.target)
        if cmp_expr is None:
            return False
        cmp_lb = 0

        # populate whitelist_edges
        assert jump_table.jumptable_entries is not None

        # sanity check: case nodes are successors to node_a. all case nodes must have at most common one successor
        node_pred = None
        if graph.in_degree[node] == 1:
            node_pred = next(iter(graph.predecessors(node)))

        case_nodes = list(graph.successors(node))

        # case 1: the common successor happens to be directly reachable from node_a (usually as a result of compiler
        # optimization)
        # example: touch_touch_no_switch.o:main
        r = self.switch_case_entry_node_has_common_successor_case_1(graph, jump_table, case_nodes, node_pred)

        # case 2: the common successor is not directly reachable from node_a. this is a more common case.
        if not r:
            r |= self.switch_case_entry_node_has_common_successor_case_2(graph, jump_table, case_nodes, node_pred)

        if not r:
            return False

        # un-structure IncompleteSwitchCaseNode
        if isinstance(node, IncompleteSwitchCaseNode):
            r = self._unpack_incompleteswitchcasenode(graph_raw, node)
            if not r:
                return False
            self._unpack_incompleteswitchcasenode(full_graph_raw, node)  # this shall not fail
            # update node
            node = next(iter(nn for nn in graph.nodes if nn.addr == jump_table.addr))

        case_and_entry_addrs = self._find_case_and_entry_addrs(node, graph, cmp_lb, jump_table)

        cases, _, to_remove = self._switch_build_cases(
            case_and_entry_addrs,
            node,
            node,
            None,
            graph_raw,
            full_graph_raw,
        )

        # we don't know what the end address of this switch-case structure is. let's figure it out
        switch_end_addr = self._switch_find_switch_end_addr(cases, None, {nn.addr for nn in self._region.graph})
        r = self._make_switch_cases_core(
            node,
            cmp_expr,
            cases,
            None,
            None,
            last_stmt.ins_addr,
            to_remove,
            graph_raw,
            full_graph_raw,
            node_a=None,
        )
        if not r:
            return False

        # fully structured into a switch-case. remove node from switch_case_known_heads
        if switch_end_addr is not None:
            self._switch_handle_gotos(cases, None, switch_end_addr)

        return True

    def _match_acyclic_switch_cases_address_loaded_from_memory_no_ob_check(
        self, node, graph_raw, full_graph_raw
    ) -> bool:
        if node.addr not in self.jump_tables:
            return False

        try:
            last_stmt = self.cond_proc.get_last_statement(node)
        except EmptyBlockNotice:
            return False
        if not (isinstance(last_stmt, Jump) and not isinstance(last_stmt.target, Const)):
            return False

        jump_table = self.jump_tables[node.addr]
        if jump_table.type != IndirectJumpType.Jumptable_AddressLoadedFromMemory:
            return False

        # extract the index expression, lower-, and upper-bounds from the last statement
        index = switch_extract_bitwiseand_jumptable_info(last_stmt)
        if not index:
            return False
        index_expr, cmp_lb, cmp_ub = index  # pylint:disable=unused-variable
        case_count = cmp_ub - cmp_lb + 1

        # ensure we have the same number of cases
        assert jump_table.jumptable_entries is not None
        if case_count != len(jump_table.jumptable_entries):
            return False

        # populate whitelist_edges
        for case_node_addr in jump_table.jumptable_entries:
            self.whitelist_edges.add((node.addr, case_node_addr))
        self.switch_case_known_heads.add(node)

        graph = _f(graph_raw)

        # sanity check: case nodes are successors to node. all case nodes must have at most common one successor
        node_pred = None
        if graph.in_degree[node] == 1:
            node_pred = next(iter(graph.predecessors(node)))

        case_nodes = list(graph.successors(node))

        # case 1: the common successor happens to be directly reachable from node_a (usually as a result of compiler
        # optimization)
        # example: touch_touch_no_switch.o:main
        r = self.switch_case_entry_node_has_common_successor_case_1(graph, jump_table, case_nodes, node_pred)

        # case 2: the common successor is not directly reachable from node_a. this is a more common case.
        if not r:
            r |= self.switch_case_entry_node_has_common_successor_case_2(graph, jump_table, case_nodes, node_pred)

        if not r:
            return False

        case_and_entry_addrs = self._find_case_and_entry_addrs(node, graph, cmp_lb, jump_table)

        cases, node_default, to_remove = self._switch_build_cases(
            case_and_entry_addrs,
            node,
            node,
            None,
            graph_raw,
            full_graph_raw,
        )

        assert node_default is None
        switch_end_addr = self._switch_find_switch_end_addr(cases, node_default, {nn.addr for nn in self._region.graph})

        r = self._make_switch_cases_core(
            node,
            index_expr,
            cases,
            None,
            None,
            last_stmt.ins_addr,
            to_remove,
            graph_raw,
            full_graph_raw,
            node_a=None,
        )
        if not r:
            return False

        # fully structured into a switch-case. remove node from switch_case_known_heads
        self.switch_case_known_heads.remove(node)
        if switch_end_addr is not None:
            self._switch_handle_gotos(cases, node_default, switch_end_addr)

        return True

    def _match_acyclic_switch_cases_address_computed(
        self, node, graph_raw: networkx.DiGraph, full_graph_raw: networkx.DiGraph
    ) -> bool:
        if node.addr not in self.jump_tables:
            return False
        jump_table = self.jump_tables[node.addr]
        if jump_table.type != IndirectJumpType.Jumptable_AddressComputed:
            return False

        try:
            last_stmts = self.cond_proc.get_last_statements(node)
        except EmptyBlockNotice:
            return False
        if len(last_stmts) != 1:
            return False
        last_stmt = last_stmts[0]

        if not isinstance(last_stmt, ConditionalJump):
            return False

        # Typical look:
        #   t2 = (r5<4> - 0x22<32>)
        #   if ((t2 <= 0x1c<32>)) { Goto (0x41d10c<32> + (t2 << 0x2<8>)) } else { Goto 0x41d108<32> }
        #
        # extract the comparison expression, lower-, and upper-bounds from the last statement
        cmp = switch_extract_cmp_bounds(last_stmt)
        if not cmp:
            return False
        cmp_expr, cmp_lb, cmp_ub = cmp  # pylint:disable=unused-variable

        if isinstance(last_stmt.false_target, Const):
            default_addr = last_stmt.false_target.value
            assert isinstance(default_addr, int)
        else:
            return False

        graph = _f(graph_raw)
        full_graph = _f(full_graph_raw)

        node_default = self._switch_find_default_node(graph, node, default_addr)
        if node_default is not None:
            # ensure we have successfully structured node_default
            if full_graph.out_degree[node_default] > 1:
                return False

        case_and_entry_addrs = self._find_case_and_entry_addrs(node, graph, cmp_lb, jump_table)

        cases, node_default, to_remove = self._switch_build_cases(
            case_and_entry_addrs,
            node,
            node,
            default_addr,
            graph_raw,
            full_graph_raw,
        )
        if node_default is None:
            # there must be a default case
            return False

        return self._make_switch_cases_core(
            node, cmp_expr, cases, default_addr, node_default, node.addr, to_remove, graph_raw, full_graph_raw
        )

    def _match_acyclic_incomplete_switch_cases(
        self, node, graph_raw: networkx.DiGraph, full_graph_raw: networkx.DiGraph
    ) -> bool:
        # sanity checks
        if node.addr not in self.jump_tables:
            return False
        if isinstance(node, IncompleteSwitchCaseNode):
            return False
        if is_empty_or_label_only_node(node):
            return False

        graph = _f(graph_raw)
        full_graph = _f(full_graph_raw)

        successors = list(graph.successors(node))

        jump_table = self.jump_tables[node.addr]
        assert jump_table.jumptable_entries is not None
        if (
            successors
            and {succ.addr for succ in successors} == set(jump_table.jumptable_entries)
            and all(graph.in_degree[succ] == 1 for succ in successors)
        ):
            out_nodes = set()
            for succ in successors:
                out_nodes |= {
                    succ for succ in full_graph.successors(succ) if succ is not node and succ not in successors
                }
            out_nodes = list(out_nodes)
            if len(out_nodes) <= 1 and node.addr not in self._matched_incomplete_switch_case_addrs:
                self._matched_incomplete_switch_case_addrs.add(node.addr)
                new_node = IncompleteSwitchCaseNode(node.addr, node, successors)
                graph_raw.remove_nodes_from(successors)
                self.replace_nodes(graph_raw, node, new_node)
                if out_nodes and out_nodes[0] in graph:
                    graph_raw.add_edge(new_node, out_nodes[0])
                full_graph_raw.remove_nodes_from(successors)
                self.replace_nodes(full_graph_raw, node, new_node, update_node_order=True)
                if out_nodes:
                    full_graph_raw.add_edge(new_node, out_nodes[0])
                if self._node_order:
                    self._node_order[new_node] = self._node_order[node]
                return True
        return False

    def _switch_build_cases(
        self,
        case_and_entryaddrs: dict[int, int | tuple[int, int | None]],
        head_node,
        node_a: BaseNode,
        node_b_addr: int | None,
        graph_raw: networkx.DiGraph,
        full_graph_raw: networkx.DiGraph,
    ) -> tuple[OrderedDict, Any, set[Any]]:
        cases: OrderedDict[int | tuple[int, ...], SequenceNode] = OrderedDict()
        to_remove = set()

        graph = _f(graph_raw)

        default_node_candidates = (
            [nn for nn in graph.nodes if nn.addr == node_b_addr] if node_b_addr is not None else []
        )
        node_default = (
            self._switch_find_default_node(graph, head_node, node_b_addr) if node_b_addr is not None else None
        )
        if node_default is not None and not isinstance(node_default, SequenceNode):
            # make the default node a SequenceNode so that we can insert Break and Continue nodes into it later
            new_node = SequenceNode(node_default.addr, nodes=[node_default])
            self.replace_nodes(graph_raw, node_default, new_node)
            self.replace_nodes(full_graph_raw, node_default, new_node, update_node_order=True)
            node_default = new_node

        converted_nodes: dict[tuple[int, int | None], Any] = {}
        entry_addr_to_ids: defaultdict[tuple[int, int | None], set[int]] = defaultdict(set)

        # the default node might get duplicated (e.g., by EagerReturns). we detect if a duplicate of the default node
        # (node b) is a successor node of node a. we only skip those entries going to the default node if no duplicate
        # of default node exists in node a's successors.
        node_a_successors = list(graph.successors(node_a))
        if len(default_node_candidates) > 1:
            node_b_in_node_a_successors = any(nn for nn in node_a_successors if nn in default_node_candidates)
        else:
            # the default node is not duplicated
            node_b_in_node_a_successors = False

        for case_idx, entry_addr in case_and_entryaddrs.items():
            if isinstance(entry_addr, tuple):
                entry_addr, entry_idx = entry_addr
            else:
                entry_idx = None

            if not node_b_in_node_a_successors and entry_addr == node_b_addr:
                # jump to default or end of the switch-case structure - ignore this case
                continue

            entry_addr_to_ids[(entry_addr, entry_idx)].add(case_idx)
            if (entry_addr, entry_idx) in converted_nodes:
                continue

            if entry_addr == self._region.head.addr:
                # do not make the region head part of the switch-case construct (because it will lead to the removal
                # of the region head node). replace this entry with a goto statement later.
                entry_node = None
            else:
                entry_node = next(
                    iter(
                        nn
                        for nn in node_a_successors
                        if nn.addr == entry_addr and (not isinstance(nn, (Block, MultiNode)) or nn.idx == entry_idx)
                    ),
                    None,
                )
            if entry_node is None:
                # Missing entries. They are probably *after* the entire switch-case construct. Replace it with an empty
                # Goto node.
                case_inner_node = Block(
                    0,
                    0,
                    statements=[
                        Jump(
                            None,
                            Const(None, None, entry_addr, self.project.arch.bits),
                            target_idx=entry_idx,
                            ins_addr=0,
                            stmt_idx=0,
                        )
                    ],
                )
                case_node = SequenceNode(0, nodes=[case_inner_node])
                converted_nodes[(entry_addr, entry_idx)] = case_node
                continue

            if isinstance(entry_node, SequenceNode):
                case_node = entry_node
            else:
                case_node = SequenceNode(entry_node.addr, nodes=[entry_node])
            to_remove.add(entry_node)

            converted_nodes[(entry_addr, entry_idx)] = case_node

        for entry_addr_and_idx, converted_node in converted_nodes.items():
            assert entry_addr_and_idx in entry_addr_to_ids
            case_ids = entry_addr_to_ids[entry_addr_and_idx]
            if len(case_ids) == 1:
                cases[next(iter(case_ids))] = converted_node
            else:
                cases[tuple(sorted(case_ids))] = converted_node

        # reorganize cases to handle fallthroughs
        cases = self._reorganize_switch_cases(cases)

        return cases, node_default, to_remove

    def _make_switch_cases_core(
        self,
        head,
        cmp_expr,
        cases: OrderedDict,
        node_default_addr: int | None,
        node_default,
        addr,
        to_remove: set,
        graph: networkx.DiGraph,
        full_graph: networkx.DiGraph,
        node_a=None,
        bail_on_nonhead_outedges: bool = False,
    ) -> bool:
        scnode = SwitchCaseNode(cmp_expr, cases, node_default, addr=addr)

        # insert the switch-case node to the graph
        other_nodes_inedges = []
        out_edges = []

        # remove all those entry nodes
        if node_default is not None:
            to_remove.add(node_default)

        for nn in to_remove:
            if nn is head or (node_a is not None and nn is node_a):
                continue
            for src in graph.predecessors(nn):
                if src not in to_remove:
                    other_nodes_inedges.append((src, nn))
            for dst in full_graph.successors(nn):
                if dst not in to_remove:
                    out_edges.append((nn, dst))

        if bail_on_nonhead_outedges:
            nonhead_out_nodes = {edge[1] for edge in out_edges if edge[1] is not head}
            if len(nonhead_out_nodes) > 1:
                # not ready to be structured yet - do it later
                return False

        # check if structuring will create any dangling nodes
        for case_node in to_remove:
            if case_node is not node_default and case_node is not node_a and case_node is not head:
                for succ in graph.successors(case_node):
                    if (
                        succ is not case_node
                        and succ is not head
                        and succ is not self._region.head
                        and graph.in_degree[succ] == 1
                    ):
                        # succ will be dangling - not ready to be structured yet - do it later
                        return False
        succs = {dst for _, dst in out_edges}
        dangling_succs = set()
        if len(succs) > 1:
            for succ in succs:
                if succ in graph:
                    non_switch_preds = {pred for pred in graph.predecessors(succ) if pred not in to_remove}
                    if not non_switch_preds:
                        dangling_succs.add(succ)
        if len(dangling_succs) > 1:
            # there will definitely be dangling nodes after structuring. it's not ready to be structured yet.
            return False

        if node_default is not None:
            # the head no longer goes to the default case
            if graph.has_edge(head, node_default):
                pass
            graph.remove_edge(head, node_default)
            full_graph.remove_edge(head, node_default)
        elif node_default_addr is not None:
            # the default node is not in the current graph, but it might be in the full graph
            node_default_in_full_graph = next(iter(nn for nn in full_graph if nn.addr == node_default_addr), None)
            if node_default_in_full_graph is not None and full_graph.has_edge(head, node_default_in_full_graph):
                # the head no longer jumps to the default node - the switch jumps to it
                full_graph.remove_edge(head, node_default_in_full_graph)

        for nn in to_remove:
            graph.remove_node(nn)
            full_graph.remove_node(nn)

        graph.add_edge(head, scnode)
        full_graph.add_edge(head, scnode)
        if self._node_order is not None:
            self._node_order[scnode] = self._node_order[head]

        if out_edges:
            # sort out_edges
            out_edges_to_head = [edge for edge in out_edges if edge[1] is head]
            other_out_edges = sorted(
                [edge for edge in out_edges if edge[1] is not head], key=lambda edge: (edge[0].addr, edge[1].addr)
            )

            # for all out edges going to head, we ensure there is a goto at the end of each corresponding case node
            for out_src, out_dst in out_edges_to_head:
                assert out_dst is head
                all_case_nodes = list(cases.values())
                if node_default is not None:
                    all_case_nodes.append(node_default)
                case_node: SequenceNode = next(nn for nn in all_case_nodes if nn.addr == out_src.addr)
                try:
                    case_node_last_stmt = self.cond_proc.get_last_statement(case_node)
                except EmptyBlockNotice:
                    case_node_last_stmt = None
                if not isinstance(case_node_last_stmt, Jump):
                    jump_stmt = Jump(
                        None, Const(None, None, head.addr, self.project.arch.bits), None, ins_addr=out_src.addr
                    )
                    jump_node = Block(out_src.addr, 0, statements=[jump_stmt])
                    case_node.nodes.append(jump_node)

            if out_edges_to_head:  # noqa:SIM108
                # add an edge from SwitchCaseNode to head so that a loop will be structured later
                out_dst_succ = head
            else:
                # add an edge from SwitchCaseNode to its most immediate successor (if there is one)
                out_dst_succ = other_out_edges[0][1] if other_out_edges else None

            if out_dst_succ is not None:
                if out_dst_succ in graph:
                    graph.add_edge(scnode, out_dst_succ)
                full_graph.add_edge(scnode, out_dst_succ)
                if full_graph.has_edge(head, out_dst_succ):
                    full_graph.remove_edge(head, out_dst_succ)

            # fix full_graph if needed: remove successors that are no longer needed
            for _out_src, out_dst in other_out_edges:
                if (
                    out_dst is not out_dst_succ
                    and out_dst in full_graph
                    and out_dst not in graph
                    and full_graph.in_degree[out_dst] == 0
                ):
                    full_graph.remove_node(out_dst)
                    assert self._region.successors is not None
                    if out_dst in self._region.successors:
                        self._region.successors.remove(out_dst)

        # remove the last statement (conditional jump) in the head node
        self._remove_last_statement_if_jump_or_schead(head)

        if node_a is not None:
            # remove the last statement in node_a
            remove_last_statements(node_a)

        return True

    @staticmethod
    def _find_case_and_entry_addrs(
        jump_head, graph, cmp_lb: int, jump_table
    ) -> dict[int, int | tuple[int, int | None]]:
        case_and_entry_addrs = {}

        addr_to_entry_nodes = defaultdict(list)
        for succ in graph.successors(jump_head):
            addr_to_entry_nodes[succ.addr].append(succ)

        for i, entry_addr in enumerate(jump_table.jumptable_entries):
            case_no = cmp_lb + i
            if entry_addr in addr_to_entry_nodes and isinstance(addr_to_entry_nodes[entry_addr][0], (MultiNode, Block)):
                case_and_entry_addrs[case_no] = entry_addr, addr_to_entry_nodes[entry_addr][0].idx
            else:
                case_and_entry_addrs[case_no] = entry_addr

        return case_and_entry_addrs

    def _is_node_unstructured_switch_case_head(self, node) -> bool:
        if node.addr in self.jump_tables:
            # maybe it has been structured?
            try:
                last_stmts = self.cond_proc.get_last_statements(node)
            except EmptyBlockNotice:
                return False
            return len(last_stmts) == 1 and isinstance(last_stmts[0], Jump)
        return False

    def _is_switch_cases_address_loaded_from_memory_head_or_jumpnode(self, graph, node) -> bool:
        if self._is_node_unstructured_switch_case_head(node):
            return True
        for succ in graph.successors(node):
            if self._is_node_unstructured_switch_case_head(succ):
                return True
        return node in self.switch_case_known_heads

    # other acyclic schemas

    def _match_acyclic_sequence(self, graph_raw, full_graph_raw, start_node) -> bool:
        """
        Check if there is a sequence of regions, where each region has a single predecessor and a single successor.
        """

        full_graph = _f(full_graph_raw)
        graph = _f(graph_raw)

        succs = list(graph.successors(start_node))
        if len(succs) == 1:
            end_node = succs[0]
            if (
                full_graph.out_degree[start_node] == 1
                and full_graph.in_degree[end_node] == 1
                and not full_graph.has_edge(end_node, start_node)
                and not self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, end_node)
                and not self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, start_node)
                and end_node not in self.dowhile_known_tail_nodes
                and not isinstance(end_node, IncompleteSwitchCaseNode)
            ):
                # merge two blocks
                new_seq = self._merge_nodes(start_node, end_node)

                # on the original graph
                self.replace_nodes(graph_raw, start_node, new_seq, old_node_1=end_node if end_node in graph else None)
                # on the graph with successors
                self.replace_nodes(full_graph_raw, start_node, new_seq, old_node_1=end_node, update_node_order=True)
                return True
        return False

    def _match_acyclic_ite(self, graph_raw, full_graph_raw, start_node) -> bool:
        """
        Check if start_node is the beginning of an If-Then-Else region. Create a Condition node if it is the case.
        """

        full_graph = _f(full_graph_raw)
        graph = _f(graph_raw)

        succs = list(full_graph.successors(start_node))
        if len(succs) == 2:
            left, right = succs
            if left.addr > right.addr:
                left, right = right, left
            if self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(
                full_graph, left
            ) or self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, right):
                # structure the switch-case first before we wrap them into an ITE. give up
                return False

            left_succs = list(full_graph.successors(left))
            right_succs = list(full_graph.successors(right))

            if (
                left in graph
                and right in graph
                and (
                    (not left_succs and not right_succs)
                    or (not left_succs and len(right_succs) == 1)
                    or (not right_succs and len(left_succs) == 1)
                    or (len(left_succs) == 1 and left_succs == right_succs)
                )
            ):
                # potentially ITE
                if (
                    full_graph.in_degree[left] == 1
                    and full_graph.in_degree[right] == 1
                    and not self._is_node_unstructured_switch_case_head(left)
                    and not self._is_node_unstructured_switch_case_head(right)
                ):
                    if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, right):
                        # c = !c
                        edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                        last_if_jump = self._remove_last_statement_if_jump(start_node)
                        new_cond_node = ConditionNode(
                            last_if_jump.ins_addr if last_if_jump is not None else start_node.addr,
                            None,
                            edge_cond_left,
                            left,
                            false_node=right,
                        )
                        new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                        if not left_succs:
                            # on the original graph
                            if left in graph:
                                graph_raw.remove_node(left)
                            self.replace_nodes(graph_raw, start_node, new_node, old_node_1=right)
                            # on the graph with successors
                            full_graph_raw.remove_node(left)
                            self.replace_nodes(
                                full_graph_raw, start_node, new_node, old_node_1=right, update_node_order=True
                            )
                        else:
                            # on the original graph
                            if right in graph:
                                graph_raw.remove_node(right)
                            self.replace_nodes(graph_raw, start_node, new_node, old_node_1=left)
                            # on the graph with successors
                            full_graph_raw.remove_node(right)
                            self.replace_nodes(
                                full_graph_raw, start_node, new_node, old_node_1=left, update_node_order=True
                            )

                        return True

            if right in graph and not right_succs and full_graph.in_degree[right] == 1 and left in graph:
                # swap them
                left, right = right, left
                left_succs, right_succs = right_succs, left_succs
            if left in graph and not left_succs and full_graph.in_degree[left] == 1 and right in graph:
                # potentially If-Then
                if not self._is_node_unstructured_switch_case_head(
                    left
                ) and not self._is_node_unstructured_switch_case_head(right):
                    if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, right):
                        # c = !c
                        edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                        last_if_jump = self._remove_last_statement_if_jump(start_node)
                        new_cond_node = ConditionNode(
                            last_if_jump.ins_addr if last_if_jump is not None else start_node.addr,
                            None,
                            edge_cond_left,
                            left,
                            false_node=None,
                        )
                        new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                        # on the original graph
                        self.replace_nodes(graph_raw, start_node, new_node, old_node_1=left)
                        # on the graph with successors
                        self.replace_nodes(
                            full_graph_raw, start_node, new_node, old_node_1=left, update_node_order=True
                        )

                        return True

            if len(right_succs) == 1 and right_succs[0] == left:
                # swap them
                left, right = right, left
                left_succs, right_succs = right_succs, left_succs
            # potentially If-Then
            if (
                left in graph
                and len(left_succs) == 1
                and left_succs[0] == right
                and full_graph.in_degree[left] == 1
                and full_graph.in_degree[right] >= 2
            ):
                if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, right):
                    # c = !c
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                    last_if_jump = self._remove_last_statement_if_jump(start_node)
                    new_cond_node = ConditionNode(
                        last_if_jump.ins_addr if last_if_jump is not None else start_node.addr,
                        None,
                        edge_cond_left,
                        left,
                        false_node=None,
                    )
                    new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                    # on the original graph
                    self.replace_nodes(graph_raw, start_node, new_node, old_node_1=left)
                    # on the graph with successors
                    self.replace_nodes(full_graph_raw, start_node, new_node, old_node_1=left, update_node_order=True)

                    return True

            if right in graph and left not in graph:
                # swap them
                left, right = right, left
                left_succs, right_succs = right_succs, left_succs  # pylint:disable=unused-variable
            # potentially If-then
            if (
                left in graph
                and right not in graph
                and full_graph.in_degree[left] == 1
                and (
                    (full_graph.in_degree[right] == 2 and left_succs == [right])
                    or (full_graph.in_degree[right] == 1 and not left_succs)
                )
            ):
                if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, right):
                    # c = !c
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                    try:
                        last_stmt = self.cond_proc.get_last_statement(start_node)
                    except EmptyBlockNotice:
                        last_stmt = None
                    new_cond_node = ConditionNode(
                        last_stmt.ins_addr if last_stmt is not None else start_node.addr,
                        None,
                        edge_cond_left,
                        left,
                        false_node=None,
                    )
                    new_nodes = [start_node, new_cond_node]
                    if full_graph.in_degree[right] == 1:
                        # only remove the if statement when it will no longer be used later
                        self._remove_last_statement_if_jump(start_node)
                        # add a goto node at the end
                        new_jump_node = Block(
                            new_cond_node.addr if new_cond_node.addr is not None else 0x7EFF_FFFF,
                            0,
                            statements=[
                                Jump(
                                    None,
                                    Const(None, None, right.addr, self.project.arch.bits),
                                    ins_addr=new_cond_node.addr,
                                )
                            ],
                        )
                        new_nodes.append(new_jump_node)
                    new_node = SequenceNode(start_node.addr, nodes=new_nodes)

                    # on the original graph
                    self.replace_nodes(graph_raw, start_node, new_node, old_node_1=left)
                    # on the graph with successors
                    self.replace_nodes(full_graph_raw, start_node, new_node, old_node_1=left, update_node_order=True)

                    return True

        return False

    def _match_acyclic_short_circuit_conditions(
        self, graph_raw: networkx.DiGraph, full_graph_raw: networkx.DiGraph, start_node
    ) -> bool:
        """
        Check if start_node is the beginning of an If-Then-Else region with cascading short-circuit expressions as the
        condition. Create a Condition node if it is the case.
        """

        # There are four possible graph schemas.
        #
        # Type A: Cascading Or::
        #
        #     cond_node
        #     |        \
        #     |         \
        # next_cond      \
        #    ...    \     \
        #            \    |
        #             \   |
        #              \  |
        #    ...       body
        #       ...      /
        #         \ \ \ /
        #        successor
        #
        # We reduce it into if (cond || next_cond) { body }
        #
        # Type B: Cascading Or with else::
        #
        #     cond_node
        #     |        \
        #     |         \
        # next_cond      \
        #    ...    \     \
        #            \    |
        #             \   |
        #              \  |
        #    ...       body
        #      else      /
        #         \ \ \ /
        #        successor
        #
        # We reduce it into if (cond || next_cond) { body } else { else }
        #
        # Type C: Cascading And::
        #
        #     cond_node
        #     |        \
        #     |         \
        # next_cond      \
        #    ...    \     \
        #            \    |
        #             \   |
        #      \       \ /
        #       \       |
        #       body    |
        #    ...  |     |
        #         |     |
        #         \ \ \ /
        #        successor
        #
        # We reduce it into if (cond && next_cond) { body }
        #
        # Type D: Cascading And with else::
        #
        #     cond_node
        #     |        \
        #     |         \
        # next_cond      \
        #    ...    \     \
        #            \    |
        #             \   |
        #      \       \ /
        #       \       |
        #       body    |
        #    ...  |    else
        #         |     |
        #         \ \ \ /
        #        successor
        #
        # We reduce it into if (cond && next_cond) { body } else { else }

        graph = _f(graph_raw)
        full_graph = _f(full_graph_raw)

        # fast-path check to reject nodes that definitely do not work
        if full_graph.out_degree[start_node] != 2:
            return False
        next_cond_candidates = list(full_graph.successors(start_node))
        check_passed = False
        for next_cond in next_cond_candidates:
            if full_graph.out_degree[next_cond] != 2:
                continue
            for next_cond_succ in full_graph.successors(next_cond):
                if full_graph.has_edge(start_node, next_cond_succ):
                    check_passed = True
                    break
            if check_passed:
                break
        if not check_passed:
            return False

        r = self._match_acyclic_short_circuit_conditions_type_a(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, right, left_right_cond, succ = r
            # create the condition node
            left_cond_expr = self.cond_proc.convert_claripy_bool_ast(left_cond)
            left_cond_expr_neg = UnaryOp(None, "Not", left_cond_expr, ins_addr=start_node.addr)
            left_right_cond_expr = self.cond_proc.convert_claripy_bool_ast(left_right_cond)
            if not self._is_single_statement_block(left):
                if not self._should_use_multistmtexprs(left):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(left)
                assert stmts is not None
                left_right_cond_expr = MultiStatementExpression(None, stmts, left_right_cond_expr, ins_addr=left.addr)
            cond = BinaryOp(None, "LogicalOr", [left_cond_expr_neg, left_right_cond_expr], ins_addr=start_node.addr)
            cond_jump = ConditionalJump(
                None,
                cond,
                Const(None, None, right.addr, self.project.arch.bits),
                Const(None, None, succ.addr, self.project.arch.bits),
                true_target_idx=right.idx if isinstance(right, (Block, MultiNode)) else None,
                false_target_idx=succ.idx if isinstance(succ, (Block, MultiNode)) else None,
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes(graph_raw, start_node, new_node, old_node_1=left if left in graph else None)
            self.replace_nodes(full_graph_raw, start_node, new_node, old_node_1=left, update_node_order=True)

            return True

        r = self._match_acyclic_short_circuit_conditions_type_b(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, right, right_left_cond, else_node = r
            # create the condition node
            left_cond_expr = self.cond_proc.convert_claripy_bool_ast(left_cond)
            right_left_cond_expr = self.cond_proc.convert_claripy_bool_ast(right_left_cond)
            if not self._is_single_statement_block(right):
                if not self._should_use_multistmtexprs(right):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(right)
                assert stmts is not None
                right_left_cond_expr = MultiStatementExpression(None, stmts, right_left_cond_expr, ins_addr=left.addr)
            cond = BinaryOp(None, "LogicalOr", [left_cond_expr, right_left_cond_expr], ins_addr=start_node.addr)
            cond_jump = ConditionalJump(
                None,
                cond,
                Const(None, None, left.addr, self.project.arch.bits, ins_addr=start_node.addr),
                Const(None, None, else_node.addr, self.project.arch.bits, ins_addr=start_node.addr),
                true_target_idx=left.idx if isinstance(left, (Block, MultiNode)) else None,
                false_target_idx=else_node.idx if isinstance(else_node, (Block, MultiNode)) else None,
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes(graph_raw, start_node, new_node, old_node_1=right if right in graph else None)
            self.replace_nodes(full_graph_raw, start_node, new_node, old_node_1=right, update_node_order=True)

            return True

        r = self._match_acyclic_short_circuit_conditions_type_c(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, succ, left_succ_cond, right = r
            # create the condition node
            left_cond_expr = self.cond_proc.convert_claripy_bool_ast(left_cond)
            left_succ_cond_expr = self.cond_proc.convert_claripy_bool_ast(left_succ_cond)
            if not self._is_single_statement_block(left):
                if not self._should_use_multistmtexprs(left):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(left)
                assert stmts is not None
                left_succ_cond_expr = MultiStatementExpression(None, stmts, left_succ_cond_expr, ins_addr=left.addr)
            left_succ_cond_expr_neg = UnaryOp(None, "Not", left_succ_cond_expr, ins_addr=start_node.addr)
            cond = BinaryOp(None, "LogicalAnd", [left_cond_expr, left_succ_cond_expr_neg], ins_addr=start_node.addr)
            cond_jump = ConditionalJump(
                None,
                cond,
                Const(None, None, right.addr, self.project.arch.bits),
                Const(None, None, succ.addr, self.project.arch.bits),
                true_target_idx=right.idx if isinstance(right, (Block, MultiNode)) else None,
                false_target_idx=succ.idx if isinstance(succ, (Block, MultiNode)) else None,
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes(graph_raw, start_node, new_node, old_node_1=left if left in graph else None)
            self.replace_nodes(full_graph_raw, start_node, new_node, old_node_1=left, update_node_order=True)
            return True

        r = self._match_acyclic_short_circuit_conditions_type_d(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, right, right_left_cond, else_node = r
            # create the condition node
            left_cond_expr = self.cond_proc.convert_claripy_bool_ast(left_cond)
            left_right_cond_expr = self.cond_proc.convert_claripy_bool_ast(right_left_cond)
            if not self._is_single_statement_block(left):
                if not self._should_use_multistmtexprs(left):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(left)
                assert stmts is not None
                left_right_cond_expr = MultiStatementExpression(None, stmts, left_right_cond_expr, ins_addr=left.addr)
            cond = BinaryOp(None, "LogicalAnd", [left_cond_expr, left_right_cond_expr], ins_addr=start_node.addr)
            cond_jump = ConditionalJump(
                None,
                cond,
                Const(None, None, right.addr, self.project.arch.bits),
                Const(None, None, else_node.addr, self.project.arch.bits),
                true_target_idx=right.idx if isinstance(right, (Block, MultiNode)) else None,
                false_target_idx=else_node.idx if isinstance(else_node, (Block, MultiNode)) else None,
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes(graph_raw, start_node, new_node, old_node_1=left if left in graph else None)
            self.replace_nodes(full_graph_raw, start_node, new_node, old_node_1=left, update_node_order=True)
            return True

        return False

    def _match_acyclic_short_circuit_conditions_type_a(  # pylint:disable=unused-argument
        self, graph, full_graph, start_node
    ) -> tuple | None:
        #   if (a) goto right
        #   else if (b) goto right
        #   else goto other_succ
        # right:
        #   ...
        #   goto other_succ
        # other_succ:

        succs = list(full_graph.successors(start_node))
        if len(succs) == 2:
            left, right = succs

            if full_graph.in_degree[left] > 1 and full_graph.in_degree[right] == 1:
                left, right = right, left

            # ensure left and right nodes are not the head of a switch-case construct
            if self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(
                full_graph, left
            ) or self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, right):
                return None

            if (
                self._is_sequential_statement_block(left)
                and full_graph.in_degree[left] == 1
                and full_graph.in_degree[right] >= 1
            ):
                if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, right):
                    # c0 = !c0
                    left_succs = list(full_graph.successors(left))
                    if len(left_succs) == 2 and right in left_succs:
                        other_succ = next(iter(succ for succ in left_succs if succ is not right))
                        if full_graph.out_degree[right] == 1 and full_graph.has_edge(right, other_succ):
                            # there must be an edge between right and other_succ
                            if self.cond_proc.have_opposite_edge_conditions(full_graph, left, right, other_succ):
                                # c1 = !c1
                                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                                edge_cond_left_right = self.cond_proc.recover_edge_condition(full_graph, left, right)
                                return left, edge_cond_left, right, edge_cond_left_right, other_succ
        return None

    def _match_acyclic_short_circuit_conditions_type_b(  # pylint:disable=unused-argument
        self, graph, full_graph, start_node
    ) -> tuple | None:
        #   if (a) goto left
        # right:
        #   else if (b) goto left
        #   else goto else_node
        # left:
        #   ...
        #   goto succ
        # else_node:
        #   ...
        #   goto succ
        # succ:

        succs = list(full_graph.successors(start_node))
        if len(succs) == 2:
            left, right = succs

            if full_graph.in_degree[left] == 1 and full_graph.in_degree[right] >= 2:
                left, right = right, left

            # ensure left and right nodes are not the head of a switch-case construct
            if self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(
                full_graph, left
            ) or self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, right):
                return None

            if (
                self._is_sequential_statement_block(right)
                and full_graph.in_degree[left] >= 2
                and full_graph.in_degree[right] == 1
            ):
                if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, right):
                    # c0 = !c0
                    right_succs = list(full_graph.successors(right))
                    left_succs = list(full_graph.successors(left))
                    if len(right_succs) == 2 and left in right_succs:
                        else_node = next(iter(succ for succ in right_succs if succ is not left))
                        if len([succ for succ in left_succs if succ is not else_node]) == 1:
                            if self.cond_proc.have_opposite_edge_conditions(full_graph, right, left, else_node):
                                # c1 = !c1
                                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                                edge_cond_right_left = self.cond_proc.recover_edge_condition(full_graph, right, left)
                                return left, edge_cond_left, right, edge_cond_right_left, else_node
        return None

    def _match_acyclic_short_circuit_conditions_type_c(  # pylint:disable=unused-argument
        self, graph, full_graph, start_node
    ) -> tuple | None:
        #   if (a) goto successor
        #   else if (b) goto successor
        # right:
        #   ...
        # successor:

        succs = list(full_graph.successors(start_node))
        if len(succs) == 2:
            left, successor = succs

            if full_graph.in_degree[left] > 1 and full_graph.in_degree[successor] == 1:
                left, successor = successor, left

            # ensure left and successor nodes are not the head of a switch-case construct
            if self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(
                full_graph, left
            ) or self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, successor):
                return None

            if (
                self._is_sequential_statement_block(left)
                and full_graph.in_degree[left] == 1
                and full_graph.in_degree[successor] >= 1
            ):
                if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, successor):
                    # c0 = !c0
                    left_succs = list(full_graph.successors(left))
                    if len(left_succs) == 2 and successor in left_succs:
                        right = next(iter(succ for succ in left_succs if succ is not successor))
                        if full_graph.out_degree[right] == 1 and full_graph.has_edge(right, successor):
                            # there must be an edge from right to successor
                            if self.cond_proc.have_opposite_edge_conditions(full_graph, left, right, successor):
                                # c1 = !c1
                                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                                edge_cond_left_successor = self.cond_proc.recover_edge_condition(
                                    full_graph, left, successor
                                )
                                return left, edge_cond_left, successor, edge_cond_left_successor, right
        return None

    def _match_acyclic_short_circuit_conditions_type_d(  # pylint:disable=unused-argument
        self, graph, full_graph, start_node
    ) -> tuple | None:
        #   if (a) goto else_node
        # left:
        #   else if (b) goto else_node
        # right:
        #   ...
        #   goto successor
        # else_node:
        #   ...
        #   goto successor
        # successor:

        succs = list(full_graph.successors(start_node))
        if len(succs) == 2:
            left, else_node = succs

            if full_graph.in_degree[left] > 1 and full_graph.in_degree[else_node] == 1:
                left, else_node = else_node, left

            # ensure left and else nodes are not the head of a switch-case construct
            if self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(
                full_graph, left
            ) or self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, else_node):
                return None

            if (
                self._is_sequential_statement_block(left)
                and full_graph.in_degree[left] == 1
                and full_graph.in_degree[else_node] >= 1
            ):
                if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, else_node):
                    # c0 = !c0
                    left_succs = list(full_graph.successors(left))
                    if len(left_succs) == 2 and else_node in left_succs:
                        right = next(iter(succ for succ in left_succs if succ is not else_node))
                        if self.cond_proc.have_opposite_edge_conditions(full_graph, left, right, else_node):
                            # c1 = !c1
                            edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                            edge_cond_left_right = self.cond_proc.recover_edge_condition(full_graph, left, right)
                            return left, edge_cond_left, right, edge_cond_left_right, else_node
        return None

    def _last_resort_refinement(self, head, graph_raw: networkx.DiGraph, full_graph_raw: networkx.DiGraph) -> bool:
        if self._improve_algorithm:
            while self._edge_virtualization_hints:
                src, dst = self._edge_virtualization_hints.pop(0)
                if _f(graph_raw).has_edge(src, dst):
                    self._virtualize_edge(graph_raw, full_graph_raw, src, dst)
                    l.debug("last_resort: Removed edge %r -> %r (type 3)", src, dst)
                    return True

        # virtualize an edge to allow progressing in structuring
        all_edges_wo_dominance = []  # to ensure determinism, edges in this list are ordered by a tuple of
        # (src_addr, dst_addr)
        secondary_edges = []  # likewise, edges in this list are ordered by a tuple of (src_addr, dst_addr)
        other_edges = []

        full_graph = _f(full_graph_raw)
        graph = _f(graph_raw)

        idoms = networkx.immediate_dominators(full_graph, head)
        if networkx.is_directed_acyclic_graph(full_graph):
            acyclic_graph = networkx.DiGraph(full_graph)
        else:
            acyclic_graph = to_acyclic_graph(full_graph, node_order=self._node_order)
        for src, dst in acyclic_graph.edges:
            if src is dst:
                continue
            if src not in graph:
                continue
            if (
                isinstance(src, Block)
                and src.statements
                and isinstance(src.statements[-1], IncompleteSwitchCaseHeadStatement)
            ):
                # this is a head of an incomplete switch-case construct (that we will definitely be structuring later),
                # so we do not want to remove any edges going out of this block
                continue
            if not dominates(idoms, src, dst) and not dominates(idoms, dst, src):
                if (src.addr, dst.addr) not in self.whitelist_edges:
                    all_edges_wo_dominance.append((src, dst))
            elif not dominates(idoms, src, dst):
                if (src.addr, dst.addr) not in self.whitelist_edges:
                    secondary_edges.append((src, dst))
            else:
                if (src.addr, dst.addr) not in self.whitelist_edges:
                    other_edges.append((src, dst))

        # acyclic graph may contain more than one entry node, so we may add a temporary head node to ensure all nodes
        # are accounted for in node_seq
        graph_entries = [nn for nn in acyclic_graph if acyclic_graph.in_degree[nn] == 0]
        postorder_head = head
        if len(graph_entries) > 1:
            postorder_head = Block(0, 0)
            for nn in graph_entries:
                acyclic_graph.add_edge(postorder_head, nn)
        ordered_nodes = list(
            reversed(list(GraphUtils.dfs_postorder_nodes_deterministic(acyclic_graph, postorder_head)))
        )
        if len(graph_entries) > 1:
            ordered_nodes.remove(postorder_head)
            acyclic_graph.remove_node(postorder_head)
        node_seq = {nn: (len(ordered_nodes) - idx) for (idx, nn) in enumerate(ordered_nodes)}  # post-order

        if all_edges_wo_dominance:
            all_edges_wo_dominance = self._order_virtualizable_edges(full_graph, all_edges_wo_dominance, node_seq)
            # virtualize the first edge
            src, dst = all_edges_wo_dominance[0]
            self._virtualize_edge(graph_raw, full_graph_raw, src, dst)
            l.debug("last_resort: Removed edge %r -> %r (type 1)", src, dst)
            return True

        if secondary_edges:
            secondary_edges = self._order_virtualizable_edges(full_graph, secondary_edges, node_seq)
            # virtualize the first edge
            src, dst = secondary_edges[0]
            self._virtualize_edge(graph_raw, full_graph_raw, src, dst)
            l.debug("last_resort: Removed edge %r -> %r (type 2)", src, dst)
            return True

        l.debug("last_resort: No edge to remove")
        return False

    def _virtualize_edge(self, graph, full_graph, src, dst):
        # if the last statement of src is a conditional jump, we rewrite it into a Condition(Jump) and a direct jump
        try:
            last_stmt = self.cond_proc.get_last_statement(src)
        except EmptyBlockNotice:
            last_stmt = None
        new_src = None
        remove_src_last_stmt = False
        if isinstance(last_stmt, ConditionalJump):
            if isinstance(last_stmt.true_target, Const) and last_stmt.true_target.value == dst.addr:
                goto0_condition = last_stmt.condition
                goto0_target = last_stmt.true_target
                goto1_target = last_stmt.false_target
            elif isinstance(last_stmt.false_target, Const) and last_stmt.false_target.value == dst.addr:
                goto0_condition = UnaryOp(None, "Not", last_stmt.condition)
                goto0_target = last_stmt.false_target
                goto1_target = last_stmt.true_target
            else:
                # this should not really happen...
                goto0_condition = None
                goto0_target = None
                goto1_target = None

            if goto0_condition is not None:
                assert goto0_target is not None and goto1_target is not None
                goto0 = Block(
                    last_stmt.ins_addr,
                    0,
                    statements=[Jump(None, goto0_target, ins_addr=last_stmt.ins_addr, stmt_idx=0)],
                )
                cond_node = ConditionNode(last_stmt.ins_addr, None, goto0_condition, goto0)
                goto1_node = Block(
                    last_stmt.ins_addr,
                    0,
                    statements=[Jump(None, goto1_target, ins_addr=last_stmt.ins_addr, stmt_idx=0)],
                )
                remove_src_last_stmt = True
                new_src = SequenceNode(src.addr, nodes=[src, cond_node, goto1_node])
        elif isinstance(last_stmt, Jump):
            # do nothing
            pass
        else:
            # insert a Jump at the end
            stmt_addr = src.addr
            goto_node = Block(
                stmt_addr,
                0,
                statements=[
                    Jump(None, Const(None, None, dst.addr, self.project.arch.bits), ins_addr=stmt_addr, stmt_idx=0)
                ],
            )
            new_src = SequenceNode(src.addr, nodes=[src, goto_node])

        if graph.has_edge(src, dst):
            graph.remove_edge(src, dst)
            self.virtualized_edges.add((src, dst))
        if new_src is not None:
            self.replace_nodes(graph, src, new_src)
            if self._node_order is not None:
                self._node_order[new_src] = self._node_order[src]
        if full_graph is not None:
            self.virtualized_edges.add((src, dst))
            full_graph.remove_edge(src, dst)
            if new_src is not None:
                self.replace_nodes(full_graph, src, new_src, update_node_order=True)
        if remove_src_last_stmt:
            remove_last_statements(src)

    def _should_use_multistmtexprs(self, node: Block | BaseNode) -> bool:
        """
        The original Phoenix algorithm had no support for multi-stmt expressions, such as the following:
        if ((x = y) && z) { ... }

        There are multiple levels at which multi-stmt expressions can be used. If the Phoenix algorithm is not not
        set to be in improved mode, then we should not use multi-stmt expressions at all.
        """
        if not self._improve_algorithm:
            return False
        if self._use_multistmtexprs == MultiStmtExprMode.NEVER:
            return False
        if self._use_multistmtexprs == MultiStmtExprMode.ALWAYS:
            ctr = AILCallCounter()
            ctr.walk(node)
            return ctr.non_label_stmts <= self._multistmtexpr_stmt_threshold
        if self._use_multistmtexprs == MultiStmtExprMode.MAX_ONE_CALL:
            # count the number of calls
            ctr = AILCallCounter()
            ctr.walk(node)
            return ctr.calls <= 1 and ctr.non_label_stmts <= self._multistmtexpr_stmt_threshold
        l.warning("Unsupported enum value for _use_multistmtexprs: %s", self._use_multistmtexprs)
        return False

    @staticmethod
    def _find_node_going_to_dst(
        node: BaseNode,
        dst: Block | BaseNode,
        last=True,
        condjump_only=False,
    ) -> tuple[int | None, BaseNode | None, Block | MultiNode | BreakNode | SequenceNode | None]:
        """

        :param node:
        :param dst_addr:
        :param dst_idx:
        :return:            A tuple of (parent node, node who has a successor of dst_addr)
        """

        dst_addr = dst.addr
        dst_idx = dst.idx if isinstance(dst, Block) else ...

        class _Holder:
            """
            Holds parent_and_block and is accessible from within the handlers.
            """

            parent_and_block: list[tuple[int, Any, Block | MultiNode | BreakNode | SequenceNode]] = []
            block_id: int = -1

        def _check(last_stmt, force_condjump: bool = False):
            return (
                (
                    (force_condjump or not condjump_only)
                    and isinstance(last_stmt, Jump)
                    and isinstance(last_stmt.target, Const)
                    and last_stmt.target.value == dst_addr
                    and (dst_idx is ... or last_stmt.target_idx == dst_idx)
                )
                or (
                    isinstance(last_stmt, ConditionalJump)
                    and (
                        (
                            isinstance(last_stmt.true_target, Const)
                            and last_stmt.true_target.value == dst_addr
                            and (dst_idx is ... or last_stmt.true_target_idx == dst_idx)
                        )
                        or (
                            isinstance(last_stmt.false_target, Const)
                            and last_stmt.false_target.value == dst_addr
                            and (dst_idx is ... or last_stmt.false_target_idx == dst_idx)
                        )
                    )
                )
                or (
                    isinstance(last_stmt, IncompleteSwitchCaseHeadStatement)
                    and any(case_addr == dst_addr for _, _, _, _, case_addr in last_stmt.case_addrs)
                )
            )

        def _handle_Block(block: Block, parent=None, **kwargs):  # pylint:disable=unused-argument
            if block.statements:
                first_stmt = first_nonlabel_nonphi_statement(block)
                if first_stmt is not None:
                    # this block has content. increment the block ID counter
                    _Holder.block_id += 1

                if _check(first_stmt):
                    _Holder.parent_and_block.append((_Holder.block_id, parent, block))
                elif len(block.statements) > 1:
                    last_stmt = block.statements[-1]
                    if _check(last_stmt) or (
                        not isinstance(last_stmt, (Jump, ConditionalJump))
                        and block.addr + block.original_size == dst_addr
                    ):
                        _Holder.parent_and_block.append((_Holder.block_id, parent, block))

        def _handle_MultiNode(block: MultiNode, parent=None, **kwargs):  # pylint:disable=unused-argument
            if block.nodes and isinstance(block.nodes[-1], Block) and block.nodes[-1].statements:
                first_stmt = first_nonlabel_nonphi_statement(block)
                if first_stmt is not None:
                    # this block has content. increment the block ID counter
                    _Holder.block_id += 1
                if _check(block.nodes[-1].statements[-1]):
                    _Holder.parent_and_block.append((_Holder.block_id, parent, block))

        def _handle_BreakNode(break_node: BreakNode, parent=None, **kwargs):  # pylint:disable=unused-argument
            _Holder.block_id += 1
            if break_node.target == dst_addr or (
                isinstance(break_node.target, Const) and break_node.target.value == dst_addr
            ):
                # FIXME: idx is ignored
                _Holder.parent_and_block.append((_Holder.block_id, parent, break_node))

        def _handle_ConditionNode(cond_node: ConditionNode, parent=None, **kwargs):  # pylint:disable=unused-argument
            _Holder.block_id += 1
            if (
                isinstance(parent, SequenceNode)
                and parent.nodes
                and parent.nodes[-1] is cond_node
                and isinstance(cond_node.true_node, Block)
                and cond_node.true_node.statements
                and isinstance(cond_node.false_node, Block)
                and cond_node.false_node.statements
            ):
                if _check(cond_node.true_node.statements[-1], force_condjump=True) or _check(
                    cond_node.false_node.statements[-1], force_condjump=True
                ):
                    # we insert the parent node (the SequenceNode) instead
                    _Holder.parent_and_block.append((_Holder.block_id, None, parent))

        walker = SequenceWalker(
            handlers={
                Block: _handle_Block,
                MultiNode: _handle_MultiNode,
                BreakNode: _handle_BreakNode,
                ConditionNode: _handle_ConditionNode,
            },
            update_seqnode_in_place=False,
            force_forward_scan=True,
        )
        _Holder.block_id = -1
        walker.walk(node)
        if not _Holder.parent_and_block:
            return None, None, None
        if last:
            return _Holder.parent_and_block[-1]
        return _Holder.parent_and_block[0]

    @staticmethod
    def _unpack_sequencenode_head(graph: networkx.DiGraph, seq: SequenceNode, new_seq=None):
        if not seq.nodes:
            return False, None
        node = seq.nodes[0]
        if new_seq is None:
            # create the new sequence node if no prior-created sequence node is passed in
            new_seq = seq.copy()
            new_seq.nodes = new_seq.nodes[1:]
            if new_seq.nodes:
                new_seq.addr = new_seq.nodes[0].addr

        preds = list(graph.predecessors(seq))
        succs = list(graph.successors(seq))
        graph.remove_node(seq)
        for pred in preds:
            graph.add_edge(pred, node)
        if new_seq.nodes:
            graph.add_edge(node, new_seq)
        for succ in succs:
            if succ is seq:
                graph.add_edge(new_seq, new_seq)
            else:
                graph.add_edge(new_seq, succ)
        return True, new_seq

    @staticmethod
    def _unpack_incompleteswitchcasenode(graph: networkx.DiGraph, incscnode: IncompleteSwitchCaseNode) -> bool:
        preds = list(graph.predecessors(incscnode))
        succs = list(graph.successors(incscnode))
        if len(succs) <= 1:
            graph.remove_node(incscnode)
            for pred in preds:
                graph.add_edge(pred, incscnode.head)
            for case_node in incscnode.cases:
                graph.add_edge(incscnode.head, case_node)
                if succs:
                    graph.add_edge(case_node, succs[0])
            return True
        return False

    @staticmethod
    def _count_statements(node: BaseNode | Block) -> int:
        if isinstance(node, Block):
            return sum(1 for stmt in node.statements if not isinstance(stmt, Label) and not is_phi_assignment(stmt))
        if isinstance(node, (MultiNode, SequenceNode)):
            return sum(PhoenixStructurer._count_statements(nn) for nn in node.nodes)
        return 1

    @staticmethod
    def _is_single_statement_block(node: BaseNode | Block) -> bool:
        if isinstance(node, (Block, MultiNode, SequenceNode)):
            return PhoenixStructurer._count_statements(node) == 1
        return False

    @staticmethod
    def _is_sequential_statement_block(node: BaseNode | Block) -> bool:
        """
        Examine if the node can be converted into a MultiStatementExpression object. The conversion fails if there are
        any conditional statements or goto statements before the very last statement of the node.
        """

        def _is_sequential_statement_list(stmts: list[Statement]) -> bool:
            if not stmts:
                return True
            return all(not isinstance(stmt, (ConditionalJump, Jump)) for stmt in stmts[:-1])

        def _to_statement_list(node: Block | MultiNode | SequenceNode | BaseNode) -> list[Statement]:
            if isinstance(node, Block):
                return node.statements
            if isinstance(node, MultiNode):
                # expand it
                all_statements = []
                for nn in node.nodes:
                    all_statements += _to_statement_list(nn)
                return all_statements
            if isinstance(node, SequenceNode):
                all_statements = []
                for nn in node.nodes:
                    all_statements += _to_statement_list(nn)
                return all_statements
            raise TypeError(f"Unsupported node type {type(node)}")

        try:
            stmt_list = _to_statement_list(node)
        except TypeError:
            return False
        return _is_sequential_statement_list(stmt_list)

    @staticmethod
    def _build_multistatementexpr_statements(block) -> list[Statement] | None:
        stmts = []
        if isinstance(block, (SequenceNode, MultiNode)):
            for b in block.nodes:
                stmts_ = PhoenixStructurer._build_multistatementexpr_statements(b)
                if stmts_ is None:
                    return None
                stmts += stmts_
            return stmts
        if isinstance(block, Block):
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Label):
                    continue
                if is_phi_assignment(stmt):
                    continue
                if isinstance(stmt, ConditionalJump):
                    if idx == len(block.statements) - 1:
                        continue
                    return None
                if isinstance(stmt, Jump):
                    return None
                stmts.append(stmt)
            return stmts
        return None

    @staticmethod
    def _remove_edges_except(graph: networkx.DiGraph, src, dst):
        for succ in list(graph.successors(src)):
            if succ is not src and succ is not dst:
                graph.remove_edge(src, succ)

    @staticmethod
    def _remove_first_statement_if_jump(node: BaseNode | Block | MultiNode) -> Jump | ConditionalJump | None:
        if isinstance(node, Block):
            if node.statements:
                idx = 0
                first_stmt = node.statements[idx]
                while isinstance(first_stmt, Label) or is_phi_assignment(first_stmt):
                    idx += 1
                    if idx >= len(node.statements):
                        first_stmt = None
                        break
                    first_stmt = node.statements[idx]

                if isinstance(first_stmt, (Jump, ConditionalJump)):
                    if idx == 0:
                        node.statements = node.statements[1:]
                    else:
                        node.statements = node.statements[0:idx] + node.statements[idx + 1 :]
                    return first_stmt
            return None
        if isinstance(node, MultiNode):
            for nn in node.nodes:
                if isinstance(nn, Block):
                    if not has_nonlabel_nonphi_statements(nn):
                        continue
                    return PhoenixStructurer._remove_first_statement_if_jump(nn)
                break
        return None

    # pylint: disable=unused-argument,no-self-use
    def _order_virtualizable_edges(self, graph: networkx.DiGraph, edges: list, node_seq: dict[Any, int]) -> list:
        """
        Returns a list of edges that are ordered by the best edges to virtualize first.
        """
        return PhoenixStructurer._chick_order_edges(edges, node_seq)

    @staticmethod
    def _chick_order_edges(edges: list, node_seq: dict[Any, int]) -> list:
        graph = networkx.DiGraph()
        graph.add_edges_from(edges)

        def _sort_edge(edge_):
            # this is a bit complex. we first sort based on the topological order of the destination node; edges with
            # destination nodes that are closer to the head (as specified in node_seq) should be virtualized first.
            # then we solve draws by prioritizing edges whose destination nodes are with a lower in-degree (only
            # consider the sub graph with these edges), and a few other properties.
            src, dst = edge_
            dst_in_degree = graph.in_degree[dst]
            src_out_degree = graph.out_degree[src]
            return -node_seq[dst], dst_in_degree, src_out_degree, -src.addr, -dst.addr  # type: ignore

        return sorted(edges, key=_sort_edge, reverse=True)

    def _generate_node_order(self):
        the_graph = (
            self._region.graph_with_successors if self._region.graph_with_successors is not None else self._region.graph
        )
        the_head = self._region.head
        ordered_nodes = GraphUtils.quasi_topological_sort_nodes(
            the_graph,
            loop_heads=[the_head],
        )
        self._node_order = {n: i for i, n in enumerate(ordered_nodes)}

    def replace_nodes(
        self,
        graph,
        old_node_0,
        new_node,
        old_node_1=None,
        self_loop=True,
        update_node_order: bool = False,
        drop_refinement_marks: bool = False,
    ):
        super().replace_nodes(graph, old_node_0, new_node, old_node_1=old_node_1, self_loop=self_loop)
        if drop_refinement_marks:
            for _, dst in list(graph.out_edges(new_node)):
                if "cyclic_refinement_outgoing" in graph[new_node][dst]:
                    del graph[new_node][dst]["cyclic_refinement_outgoing"]
        if self._node_order is not None and update_node_order:
            if old_node_1 is not None:
                self._node_order[new_node] = min(self._node_order[old_node_0], self._node_order[old_node_1])
            else:
                self._node_order[new_node] = self._node_order[old_node_0]

    @staticmethod
    def _replace_node_in_edge_list(edge_list: list[tuple], old_node, new_node) -> None:
        for idx in range(len(edge_list)):  # pylint:disable=consider-using-enumerate
            edge = edge_list[idx]
            src, dst = edge
            replace = False
            if src is old_node:
                src = new_node
                replace = True
            if dst is old_node:
                dst = new_node
                replace = True
            if replace:
                edge_list[idx] = src, dst

    @staticmethod
    def dump_graph(graph: networkx.DiGraph, path: str) -> None:
        graph_with_str = networkx.DiGraph()

        for node in graph:
            graph_with_str.add_node(f'"{node!r}"')

        for src, dst, data in graph.edges(data=True):
            data_dict = {} if data.get("cyclic_refinement_outgoing", False) is False else {"CRO": "True"}
            graph_with_str.add_edge(f'"{src!r}"', f'"{dst!r}"', **data_dict)

        networkx.drawing.nx_pydot.write_dot(graph_with_str, path)

    @staticmethod
    def switch_case_entry_node_has_common_successor_case_1(graph, jump_table, case_nodes, node_pred) -> bool:
        all_succs = set()
        for case_node in case_nodes:
            if case_node is node_pred:
                continue
            if case_node.addr in jump_table.jumptable_entries:
                all_succs |= set(graph.successors(case_node))

        case_node_successors = set()
        for case_node in case_nodes:
            if case_node is node_pred:
                continue
            if case_node in all_succs:
                continue
            if case_node.addr in jump_table.jumptable_entries:
                succs = set(graph.successors(case_node))
                case_node_successors |= {succ for succ in succs if succ.addr not in jump_table.jumptable_entries}

        return len(case_node_successors) <= 1

    @staticmethod
    def switch_case_entry_node_has_common_successor_case_2(graph, jump_table, case_nodes, node_pred) -> bool:
        case_node_successors = set()
        for case_node in case_nodes:
            if case_node is node_pred:
                continue
            if case_node.addr in jump_table.jumptable_entries:
                succs = set(graph.successors(case_node))
                case_node_successors |= {succ for succ in succs if succ.addr not in jump_table.jumptable_entries}

        return len(case_node_successors) <= 1
