# pylint:disable=line-too-long,import-outside-toplevel,import-error,multiple-statements,too-many-boolean-expressions
# ruff: noqa: SIM102
from __future__ import annotations

import logging
from collections import OrderedDict, defaultdict
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import claripy
import networkx

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, MultiStatementExpression, UnaryOp
from angr.ailment.statement import ConditionalJump, Jump, Label, Return, Statement
from angr.analyses.decompiler.counters.call_counter import AILCallCounter
from angr.analyses.decompiler.node_replacer import NodeReplacer
from angr.analyses.decompiler.region_overlay import RegionOverlay
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import (
    BaseNode,
    BreakNode,
    ConditionalBreakNode,
    ConditionNode,
    ContinueNode,
    EmptyBlockNotice,
    IncompleteSwitchCaseHeadStatement,
    IncompleteSwitchCaseNode,
    LoopNode,
    MultiNode,
    SequenceNode,
    SwitchCaseNode,
)
from angr.analyses.decompiler.utils import (
    extract_jump_targets,
    first_nonlabel_nonphi_statement,
    has_nonlabel_nonphi_statements,
    is_empty_or_label_only_node,
    remove_last_statement,
    remove_last_statements,
    switch_extract_bitwiseand_jumptable_info,
    switch_extract_cmp_bounds,
    switch_extract_cmp_bounds_from_condition,
    switch_extract_switch_expr_from_jump_target,
)
from angr.knowledge_plugins.cfg import IndirectJump, IndirectJumpType
from angr.utils.ail import is_head_controlled_loop_block, is_phi_assignment
from angr.utils.constants import SWITCH_MISSING_DEFAULT_NODE_ADDR
from angr.utils.graph import DirectedGraphHelper, GraphUtils, dfs_back_edges, dominates

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


class MultiStmtExprMode(StrEnum):
    """
    Mode of multi-statement expression creation during structuring.
    """

    NEVER = "Never"
    ALWAYS = "Always"
    MAX_ONE_CALL = "Only when less than one call"


class PhoenixStructurer(StructurerBase):
    """
    Structure a region using a structuring algorithm that is similar to the one in Phoenix decompiler (described in the
    "phoenix decompiler" paper). Note that this implementation has quite a few improvements over the original described
    version and *should not* be used to evaluate the performance of the original algorithm described in that paper.
    """

    NAME = "phoenix"
    SUPPORTS_OVERLAYS = True

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

        self._graph_helper: DirectedGraphHelper[Block | BaseNode] = None  # type: ignore[assignment]

        self._use_multistmtexprs = use_multistmtexprs
        self._multistmtexpr_stmt_threshold = multistmtexpr_stmt_threshold
        self._analyze()

    @staticmethod
    def _assert_graph_ok(g, msg: str) -> None:
        if _DEBUG:
            if g is None:
                return
            assert len(list(networkx.connected_components(networkx.Graph(g)))) <= 1, (
                f"{msg}: More than one connected component. Please report this."
            )
            assert len([nn for nn in g if g.in_degree[nn] == 0]) <= 1, (
                f"{msg}: More than one graph entrance. Please report this."
            )

    def _analyze(self):
        # iterate until there is only one node in the region

        # the region's identified successors (its loop-exit / break targets). these must be captured before
        # structuring begins: structuring removes the live exit edges as it forms breaks/gotos, which would empty
        # the region's derived successor set, but the break-rewrite logic still needs the original exit targets.
        self._initial_successors = set(self._region.successors) if self._region.successors is not None else set()

        self._assert_graph_ok(self._region.graph, "Incorrect region graph")

        has_cycle = self._has_cycle()

        # initialize the directed graph helper
        self._graph_helper = DirectedGraphHelper(self._region.graph_with_successors, has_cycle, self._region.head)

        # special handling for single-node loops
        if len(self._region.graph.nodes) == 1 and has_cycle:
            self._analyze_cyclic()

        # checkpoint the region prior to conducting a cyclic refinement because we may not be able to structure a
        # cycle out of the refined graph. in that case, we roll the region back and return.
        pre_refinement_checkpoint: int | None = None

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
                    pre_refinement_checkpoint = None
                    if self._region.head not in self._region.graph:
                        # update the loop head
                        self._region.head = next(
                            iter(node for node in self._region.graph.nodes if node.addr == self._region.head.addr)
                        )
                elif pre_refinement_checkpoint is None:
                    pre_refinement_checkpoint = self._region.manager.checkpoint()
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
                    self._region.raw_graph,
                    self._region.raw_graph_with_successors,
                )
                self._assert_graph_ok(self._region.graph, "Last resort refinement went wrong")
                if not removed_edge:
                    # cannot make any progress in this region. return the subgraph directly
                    break

        if len(self._region.graph.nodes) == 1:
            # successfully structured
            self.result = next(iter(self._region.graph.nodes))
        else:
            if pre_refinement_checkpoint is not None:
                # we could not make a loop after the last cycle refinement. restore the graph
                l.debug("Could not structure the cyclic graph. Restoring the region to the pre-refinement state.")
                self._region.manager.rollback(pre_refinement_checkpoint)

            self.result = None  # the actual result is in self._region.graph and self._region.graph_with_successors

    def _analyze_cyclic(self) -> bool:
        any_matches = False
        loop_heads = list(self._graph_helper.loop_heads())

        for node in reversed(self._graph_helper.sort_nodes_by_order(loop_heads)):
            if node not in self._region.graph:
                continue
            matched = self._match_cyclic_schemas(
                node,
                self._region.head,
                self._region.raw_graph,
                self._region.raw_graph_with_successors,
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
            elif len(self._initial_successors) == 1:
                # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
                self._rewrite_conditional_jumps_to_breaks(
                    loop_node.sequence_node, [succ.addr for succ in self._initial_successors]
                )
            # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
            self._rewrite_jumps_to_continues(loop_node.sequence_node)
        return matched

    def _match_cyclic_while(
        self,
        node,
        head,
        graph_raw,  # pylint:disable=unused-argument
        full_graph_raw,
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:
        full_graph = full_graph_raw.filtered()

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
                        self.replace_nodes_both(node, loop_node, self_loop=False, drop_refinement_marks=True)

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except_overlay(loop_node, right)

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

                            self.replace_nodes_both(
                                node, loop_node, old_node_1=left, self_loop=False, drop_refinement_marks=True
                            )

                            # ensure the loop has only one successor: the right node
                            self._remove_edges_except_overlay(loop_node, right)

                            return True, loop_node, right
                        # we generate a while-true loop instead
                        edge_cond_right = self.cond_proc.recover_edge_condition(full_graph_raw, head_block, right)
                        last_stmt = self._remove_last_statement_if_jump(head_block)
                        assert last_stmt is not None
                        cond_jump = Jump(
                            self.ail_manager.next_atom(),
                            Const(self.ail_manager.next_atom(), right.addr, self.project.arch.bits),
                            None,
                            ins_addr=last_stmt.tags["ins_addr"],
                        )
                        jump_node = Block(last_stmt.tags["ins_addr"], None, statements=[cond_jump])
                        cond_jump_node = ConditionNode(last_stmt.tags["ins_addr"], None, edge_cond_right, jump_node)
                        new_node = SequenceNode(node.addr, nodes=[node, cond_jump_node, left])
                        loop_node = LoopNode("while", claripy.true(), new_node, addr=node.addr)

                        self.replace_nodes_both(
                            node, loop_node, old_node_1=left, self_loop=False, drop_refinement_marks=True
                        )

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except_overlay(loop_node, right)

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

                            self.replace_nodes_both(
                                node, loop_node, old_node_1=left, self_loop=False, drop_refinement_marks=True
                            )

                            # ensure the loop has only one successor: the right node
                            self._remove_edges_except_overlay(loop_node, right)

                            return True, loop_node, right

        return False, None, None

    def _match_cyclic_while_with_single_successor(
        self, node, head, graph_raw, full_graph_raw
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:
        if self._initial_successors:
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

        for node_ in seq_node.nodes:
            if node_ is not node_copy and node_ is not node:
                self._region.remove_node(node_, absorbed_into=node, absorb_out_edges=True)
        self.replace_nodes_both(node, loop_node, self_loop=False, drop_refinement_marks=True)
        self._region.add_edge(loop_node, successor_node)

        self._graph_helper.replace_node(node, loop_node)
        self._graph_helper.replace_node(loop_node, successor_node)

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
        self,
        node,
        head,
        graph_raw,  # pylint:disable=unused-argument
        full_graph_raw,
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:
        full_graph = full_graph_raw.filtered()

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
                                        self.ail_manager.next_atom(),
                                        stmts,
                                        self.cond_proc.convert_claripy_bool_ast(edge_cond_succhead),
                                        ins_addr=succ.addr,
                                    )
                                drop_succ = True

                            new_node = SequenceNode(node.addr, nodes=[node] if drop_succ else [node, succ])
                            loop_node = LoopNode("do-while", edge_cond_succhead, new_node, addr=node.addr)

                            self.replace_nodes_both(
                                node, loop_node, old_node_1=succ, self_loop=False, drop_refinement_marks=True
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

                    self.replace_nodes_both(node, loop_node, self_loop=False, drop_refinement_marks=True)

                    return True, loop_node, succ
        return False, None, None

    def _match_cyclic_natural_loop(
        self, node, head, graph_raw, full_graph_raw
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:
        full_graph = full_graph_raw.filtered()
        graph = graph_raw.filtered()

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
                for raw_succ in full_graph_raw.successors(next_node):
                    if raw_succ is succs[0]:
                        continue
                    if full_graph_raw.edge_marked(next_node, raw_succ):
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

        for node_ in seq_node.nodes:
            if node_ is not node:
                self._region.remove_node(node_, absorbed_into=node, absorb_out_edges=True)
        self.replace_nodes_both(node, loop_node, self_loop=False, drop_refinement_marks=True)

        successor = None if not loop_successor_candidates else next(iter(loop_successor_candidates))
        if successor is not None and (successor in graph or successor in full_graph):
            self._region.add_edge(loop_node, successor)

        return True, loop_node, successor

    def _refine_cyclic(self) -> bool:
        graph = self._region.graph
        loop_heads = {t for _, t in dfs_back_edges(graph, self._region.head, visit_all_nodes=True)}
        sorted_loop_heads = self._graph_helper.sort_nodes_by_order(list(loop_heads))

        for head in sorted_loop_heads:
            l.debug("... refining cyclic at %r", head)
            refined = self._refine_cyclic_core(head, loop_heads)
            l.debug("... refined: %s", refined)
            if refined:
                self._assert_graph_ok(self._region.graph, "Refinement went wrong")
                # cyclic refinement may create dangling nodes in the full graph
                return True
        return False

    def _refine_cyclic_core(self, loop_head, loop_heads) -> bool:
        graph_raw = self._region.raw_graph
        fullgraph_raw = self._region.raw_graph_with_successors

        graph = graph_raw.filtered()
        fullgraph = fullgraph_raw.filtered()

        # check if there is an out-going edge from the loop head
        head_succs = list(fullgraph.successors(loop_head))
        successor = None  # the loop successor
        loop_type = None
        # continue_node either the loop header for while(true) loops or the loop header predecessor for do-while loops
        continue_node = loop_head

        is_while, result_while = self._refine_cyclic_is_while_loop(graph, fullgraph, loop_head, head_succs)
        is_dowhile, result_dowhile = self._refine_cyclic_is_dowhile_loop(graph, fullgraph, loop_head, loop_heads)

        continue_edges: list[tuple[BaseNode, BaseNode]] = []
        outgoing_edges: list = []

        # gotta pick one!
        # for now, we handle the most common case: both successors exist in the graph of the parent region, and
        # one successor has a path to the other successor
        if is_while and is_dowhile and self._parent_region is not None:
            assert result_while is not None and result_dowhile is not None
            succ_while = result_while[-1]
            succ_dowhile = result_dowhile[-1]
            # Check if the while matcher would produce while(true): if the
            # do-while's latch appears as a source in the while's outgoing
            # edges, the latch's condition is wasted as a break.  Prefer
            # do-while so the latch's condition becomes the loop condition.
            dowhile_latch = result_dowhile[2]  # continue_node = latch
            while_outgoing_srcs = {src for src, _ in result_while[1]}
            if dowhile_latch in while_outgoing_srcs:
                is_while = False
            elif succ_while in self._parent_region.graph and succ_dowhile in self._parent_region.graph:
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
            is_natural, result_natural = self._refine_cyclic_make_natural_loop(graph, fullgraph, loop_head, loop_heads)
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
                    #
                    # don't enter loops because we can't rewrite a goto edge as break if the jump to the loop head is
                    # inside another loop
                    _, _, src_block = self._find_node_going_to_dst(src, dst, enter_loops=False)
                    if src_block is None:
                        # we can't find the source block, which is probably because the source block is within another
                        # loop. keep that goto and remove the edge anyway
                        self._region.mark_edge(src, dst, cyclic_refinement_outgoing=True)
                    elif not isinstance(src_block, (Block, MultiNode)):
                        # it has probably been structured into BreakNode or ConditionalBreakNode
                        # just remove the edge
                        self._region.mark_edge(src, dst, cyclic_refinement_outgoing=True)
                    else:
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
                                self.ail_manager.next_atom(),
                                Const(self.ail_manager.next_atom(), successor.addr, self.project.arch.bits),
                                target_idx=successor.idx if isinstance(successor, Block) else None,
                                ins_addr=last_src_stmt.tags["ins_addr"],
                            )
                            break_node = Block(last_src_stmt.tags["ins_addr"], None, statements=[break_stmt])
                        else:
                            fallthrough_node = next(
                                iter(succ for succ in fullgraph.successors(src) if succ is not dst), None
                            )
                            if fallthrough_node is not None:
                                # we create a conditional jump that will be converted to a conditional break later
                                break_stmt = Jump(
                                    self.ail_manager.next_atom(),
                                    Const(self.ail_manager.next_atom(), successor.addr, self.project.arch.bits),
                                    target_idx=successor.idx if isinstance(successor, Block) else None,
                                    ins_addr=last_src_stmt.tags["ins_addr"],
                                )
                                break_node_inner = Block(last_src_stmt.tags["ins_addr"], None, statements=[break_stmt])
                                fallthrough_stmt = Jump(
                                    self.ail_manager.next_atom(),
                                    Const(
                                        self.ail_manager.next_atom(),
                                        fallthrough_node.addr,
                                        self.project.arch.bits,
                                    ),
                                    target_idx=successor.idx if isinstance(successor, Block) else None,
                                    ins_addr=last_src_stmt.tags["ins_addr"],
                                )
                                break_node_inner_fallthrough = Block(
                                    last_src_stmt.tags["ins_addr"], None, statements=[fallthrough_stmt]
                                )
                            else:
                                # the fallthrough node does not exist in the graph. we create a conditional jump that
                                # jumps to an address
                                if not isinstance(last_src_stmt, ConditionalJump):
                                    raise TypeError(f"Unexpected last_src_stmt type {type(last_src_stmt)}")
                                other_target = (
                                    last_src_stmt.true_target
                                    if isinstance(last_src_stmt.false_target, Const)
                                    and last_src_stmt.false_target.value == successor.addr
                                    else last_src_stmt.false_target
                                )
                                assert other_target is not None
                                break_stmt = Jump(
                                    self.ail_manager.next_atom(),
                                    Const(self.ail_manager.next_atom(), successor.addr, self.project.arch.bits),
                                    target_idx=successor.idx if isinstance(successor, Block) else None,
                                    ins_addr=last_src_stmt.tags["ins_addr"],
                                )
                                break_node_inner = Block(last_src_stmt.tags["ins_addr"], None, statements=[break_stmt])
                                fallthrough_stmt = Jump(
                                    self.ail_manager.next_atom(),
                                    other_target,
                                    target_idx=successor.idx if isinstance(successor, Block) else None,
                                    ins_addr=last_src_stmt.tags["ins_addr"],
                                )
                                break_node_inner_fallthrough = Block(
                                    last_src_stmt.tags["ins_addr"], None, statements=[fallthrough_stmt]
                                )
                            break_node = ConditionNode(
                                last_src_stmt.tags["ins_addr"],
                                None,
                                break_cond,
                                break_node_inner,
                                false_node=break_node_inner_fallthrough,
                            )
                        new_src_block = self._copy_and_remove_last_statement_if_jump(src_block)
                        new_node = SequenceNode(src_block.addr, nodes=[new_src_block, break_node])

                        # we cannot modify the original src_block because loop refinement may fail and we must restore
                        # the original graph
                        new_src = NodeReplacer(src, {src_block: new_node}).result
                        self._region.mark_edge(src, dst, cyclic_refinement_outgoing=True)
                        self.replace_nodes_both(src, new_src)
                        if src is loop_head:
                            loop_head = new_src
                        if src is continue_node:
                            continue_node = new_src

                        self._replace_node_in_edge_list(outgoing_edges, src, new_src)
                        self._replace_node_in_edge_list(continue_edges, src, new_src)

                else:
                    self.virtualized_edges.add((src, dst))
                    self._region.detach_edge(src, dst)
                    if dst in fullgraph and fullgraph.in_degree[dst] == 0:
                        # drop this node
                        self._region.remove_node(dst)

        if len(continue_edges) > 1:
            # convert all but one (the one that is the farthest from the head, topological-wise) head-going edges into
            # continues
            sorted_nodes = self._graph_helper.sort_nodes_by_order([src for src, _ in continue_edges])
            src_to_ignore = sorted_nodes[-1]
            replacements = {}

            for src, _ in continue_edges:
                if src is src_to_ignore:
                    # this edge will be handled during loop structuring
                    # mark it regardless
                    continue

                # just in case src has been replaced
                src = replacements.get(src, src)

                # due to prior structuring of sub regions, the continue node may already be a Jump statement deep in
                # src at this point. we need to find the Jump statement and replace it.
                assert continue_node is not None
                # don't enter loops because we can't rewrite a goto edge as continue if the jump to the loop head is
                # inside another loop
                _, _, cont_block = self._find_node_going_to_dst(src, continue_node, enter_loops=False)
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
                    self._region.detach_edge(src, continue_node)
                else:
                    # remove the edge.
                    self._region.detach_edge(src, continue_node)
                    # replace it with the original node plus the continue node
                    try:
                        last_stmt = self.cond_proc.get_last_statement(cont_block)
                    except EmptyBlockNotice:
                        # meh
                        last_stmt = None
                    if last_stmt is not None:
                        new_cont_node = None
                        if isinstance(last_stmt, ConditionalJump):
                            new_cont_node = ContinueNode(last_stmt.tags["ins_addr"], continue_node.addr)
                            if (
                                isinstance(last_stmt.true_target, Const)
                                and last_stmt.true_target.value == continue_node.addr
                            ):
                                new_cont_node = ConditionNode(
                                    last_stmt.tags["ins_addr"], None, last_stmt.condition, new_cont_node
                                )
                            else:
                                new_cont_node = ConditionNode(
                                    last_stmt.tags["ins_addr"],
                                    None,
                                    UnaryOp(self.ail_manager.next_atom(), "Not", last_stmt.condition),
                                    new_cont_node,
                                )
                        elif isinstance(last_stmt, Jump):
                            new_cont_node = ContinueNode(last_stmt.tags["ins_addr"], continue_node.addr)

                        if new_cont_node is not None and isinstance(cont_block, (Block, MultiNode)):
                            new_cont_block = self._copy_and_remove_last_statement_if_jump(cont_block)
                            new_node = NodeReplacer(src, {cont_block: new_cont_block}).result
                            new_src = SequenceNode(new_node.addr, nodes=[new_node, new_cont_node])
                            replacements[src] = new_src
                            self.replace_nodes_both(src, new_src)

                            if continue_node is src:
                                # set continue_node to the new node
                                continue_node = new_src

        if loop_type == "do-while":
            self.dowhile_known_tail_nodes.add(continue_node)

        return bool(outgoing_edges or len(continue_edges) > 1)

    @staticmethod
    def _refine_cyclic_determine_loop_body(graph, fullgraph, loop_head, loop_heads, successor=None) -> set[BaseNode]:
        # determine the loop body: all nodes that have paths going to loop_head
        # networkx.has_path(graph, node, loop_head) is too expensive though.
        loop_body = {loop_head}
        inverted_graph = graph.reverse_view()
        inverted_loophead_descendants = set(networkx.descendants(inverted_graph, loop_head))
        for node in networkx.descendants(fullgraph, loop_head):
            if node in graph and node in inverted_loophead_descendants:
                loop_body.add(node)

        if any(other_loop_head in loop_body for other_loop_head in loop_heads if other_loop_head is not loop_head):
            # the loop body cannot contain other loop heads
            return set()

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

                    continue_edges = sorted(continue_edges, key=lambda edge: (edge[0].addr, edge[1].addr))
                    outgoing_edges = sorted(outgoing_edges, key=lambda edge: (edge[0].addr, edge[1].addr))
                    return True, (continue_edges, outgoing_edges, loop_head, successor)
        return False, None

    def _refine_cyclic_is_dowhile_loop(
        self, graph, fullgraph, loop_head, loop_heads
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
                        graph, fullgraph, loop_head, loop_heads, successor=successor
                    )
                    for node in loop_body:
                        if node is head_pred:
                            continue
                        succs = list(fullgraph.successors(node))
                        if head_pred in succs and not self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(
                            fullgraph, node
                        ):
                            # special case: if node is the header of a switch-case, then this is *not* a continue edge
                            continue_edges.append((node, head_pred))

                        outside_succs = [succ for succ in succs if succ not in loop_body]
                        for outside_succ in outside_succs:
                            outgoing_edges.append((node, outside_succ))

                    continue_edges = sorted(continue_edges, key=lambda edge: (edge[0].addr, edge[1].addr))
                    outgoing_edges = sorted(outgoing_edges, key=lambda edge: (edge[0].addr, edge[1].addr))
                    return True, (continue_edges, outgoing_edges, continue_node, successor)
        return False, None

    @staticmethod
    def _refine_cyclic_make_natural_loop(
        graph, fullgraph, loop_head, loop_heads
    ) -> tuple[bool, tuple[list, list, Any] | None]:
        continue_edges = []
        outgoing_edges = []

        loop_body = PhoenixStructurer._refine_cyclic_determine_loop_body(graph, fullgraph, loop_head, loop_heads)
        if not loop_body:
            return False, None

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

        continue_edges = sorted(continue_edges, key=lambda edge: (edge[0].addr, edge[1].addr))
        outgoing_edges = sorted(outgoing_edges, key=lambda edge: (edge[0].addr, edge[1].addr))
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
                    self._region.raw_graph,
                    self._region.raw_graph_with_successors,
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

        for node in self._graph_helper.dfs_postorder_nodes_deterministic(head):
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

        # sanity check: all case nodes must have at most one common successor at this point
        # note that we are ignoring AIL blocks with block ID != None
        nodes = {(nn.addr, nn.idx if isinstance(nn, Block) else None): nn for nn in graph_raw.successors(node)}
        successors: set[int] = set()
        case_nodes: set[int] = set()
        for _, _, case_target_addr, case_target_idx, _ in last_stmt.case_addrs:
            case_nodes.add(case_target_addr)
            case_node = nodes.get((case_target_addr, case_target_idx))
            if case_node is None:
                continue
            successors.update(nn.addr for nn in graph_raw.successors(case_node))
        if len(successors.difference(case_nodes)) > 1:
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
        )
        fake_node_default = False
        if node_default_addr is not None and node_default is None:
            # the default node is not found. it's likely the node has been structured and is part of another construct
            # (e.g., inside another switch-case). we need to create a default node that jumps to the other node
            jmp_to_default_node = Jump(
                self.ail_manager.next_atom(),
                Const(self.ail_manager.next_atom(), node_default_addr, self.project.arch.bits),
                None,
                ins_addr=SWITCH_MISSING_DEFAULT_NODE_ADDR,
            )
            node_default = Block(SWITCH_MISSING_DEFAULT_NODE_ADDR, 0, statements=[jmp_to_default_node])
            self._region.add_edge(node, node_default)
            fake_node_default = True
            self._graph_helper.add_node_successor(node, node_default)

        r = self._make_switch_cases_core(
            node,
            self.cond_proc.claripy_ast_from_ail_condition(last_stmt.switch_variable),
            cases,
            node_default_addr,
            node_default,
            last_stmt.tags["ins_addr"],
            to_remove,
            graph_raw,
            full_graph_raw,
            bail_on_nonhead_outedges=True,
        )
        if not r:
            if fake_node_default:
                # a failed match must leave the graph unchanged: drop the fake default node we just inserted, or it
                # accumulates as a phantom successor and blocks cyclic matchers on later rounds
                self._region.remove_node(node_default)
                self._graph_helper.remove_node(node_default)
            return False

        # special handling of duplicated default nodes
        if node_default is not None and self._region.graph.out_degree[node] > 1:
            other_out_nodes = list(self._region.graph.successors(node))
            for o in other_out_nodes:
                if o.addr == node_default.addr and o is not node_default:
                    self._region.remove_node(o, absorbed_into=node_default, absorb_out_edges=True)

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
        cond_expr_or_stmt = None
        cond_case = None
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

                cond_expr_or_stmt = cond_node.condition
                cond_case = 1
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

            cond_expr_or_stmt = last_stmt
            cond_case = 2
            switch_head_addr = last_stmt.tags["ins_addr"]

        graph = graph_raw.filtered()
        full_graph = full_graph_raw.filtered()

        # special fix
        if (
            len(successor_addrs) == 2
            and graph.out_degree[node] == 2
            and len(set(successor_addrs).intersection({succ.addr for succ in graph.successors(node)})) == 1
        ):
            # there is an unmatched successor addr! fix it
            successor_addrs = [succ.addr for succ in graph.successors(node)]

        for t in successor_addrs:
            if t in self.jump_tables:
                # this is a candidate!
                target = t
                break
        else:
            return False

        # extract the comparison expression, lower-, and upper-bounds from the last statement
        match cond_case:
            case 1:
                cmp = switch_extract_cmp_bounds_from_condition(
                    self.cond_proc.convert_claripy_bool_ast(cond_expr_or_stmt)
                )
                if not cmp:
                    return False
            case 2:
                # extract the comparison expression, lower-, and upper-bounds from the last statement
                cmp = switch_extract_cmp_bounds(cond_expr_or_stmt)
                if not cmp:
                    return False
            case _:
                # unreachable!
                return False

        cmp_expr, cmp_lb, _cmp_ub = cmp  # pylint:disable=unused-variable

        jump_table = self.jump_tables[target]
        if jump_table.type != IndirectJumpType.Jumptable_AddressLoadedFromMemory:
            return False

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
            _, new_seq_node = self._unpack_sequencenode_head_overlay(node_a)
            if new_seq_node is not None:
                self._graph_helper.replace_node(node_a, new_seq_node)

            # update node_a
            node_a = next(iter(nn for nn in graph.nodes if nn.addr == target))
        if isinstance(node_a, IncompleteSwitchCaseNode):
            # special case: if node_default is None, node_a has a missing case, and node_a has a successor in the full
            # graph that is not the default node, then we know
            # 1. there is a default node (instead of the successor of the entire switch-case construct).
            # 2. the default node is in a parent region.
            # as a result, we cannot structure this switch-case right now
            if (
                len(node_a.cases) == len(set(jump_table.jumptable_entries)) - 1
                and node_default is None
                and len([succ for succ in full_graph.successors(node_a) if succ.addr != node_b_addr]) > 0
            ):
                return False

            r = self._unpack_incompleteswitchcasenode_overlay(node_a, jump_table.jumptable_entries)
            if not r:
                return False
            # update node_a
            node_a = next(iter(nn for nn in graph.nodes if nn.addr == target))
            # graph is changed; update the graph helper cache
            self._graph_helper.reset()

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
        )

        if isinstance(better_node_a, SwitchCaseNode) and better_node_a.default_node is None:
            # we found a different head for an otherwise complete edge case.
            # recreate the switch with it.
            newsc = SwitchCaseNode(better_node_a.switch_expr, better_node_a.cases, node_default, addr=node.addr)

            if node_default is not None and set(graph.succ[node_a]) != set(graph.succ[node_default]):
                # if node_a and default_node have different successors we need to bail
                return False

            region = self._region
            gws = region.graph_with_successors
            all_preds = set(gws.pred[node])
            all_succs = set(gws.succ[node_a])
            region.add_node(newsc)
            if node_default is not None:
                region.remove_node(node_default, absorbed_into=newsc)
            region.remove_node(node, absorbed_into=newsc)
            region.remove_node(node_a, absorbed_into=newsc)
            for pred in all_preds:
                region.add_edge(pred, newsc)
            for succ in all_succs:
                region.add_edge(newsc, succ)

            self._graph_helper.replace_node(better_node_a, newsc)

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

        graph = graph_raw.filtered()
        full_graph = full_graph_raw.filtered()

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
            if len(set(jump_table.jumptable_entries)) > len(node.cases):
                # it has a missing default case node! we cannot structure it as a no-default switch-case
                return False

            r = self._unpack_incompleteswitchcasenode_overlay(node, jump_table.jumptable_entries)
            if not r:
                return False
            # update node
            node = next(iter(nn for nn in graph.nodes if nn.addr == jump_table.addr))
            # _unpack_incompleteswitchcasenode_overlay() unpacks a bunch of nodes.
            # Reset the cache so it's rebuilt from the current graph.
            self._graph_helper.reset()

        case_and_entry_addrs = self._find_case_and_entry_addrs(node, graph, cmp_lb, jump_table)

        cases, _, to_remove = self._switch_build_cases(
            case_and_entry_addrs,
            node,
            node,
            None,
            graph_raw,
        )

        # we don't know what the end address of this switch-case structure is. let's figure it out
        switch_end_addr = self._switch_find_switch_end_addr(cases, None, {nn.addr for nn in self._region.graph})
        r = self._make_switch_cases_core(
            node,
            cmp_expr,
            cases,
            None,
            None,
            last_stmt.tags["ins_addr"],
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

        graph = graph_raw.filtered()

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
        )

        assert node_default is None
        switch_end_addr = self._switch_find_switch_end_addr(cases, node_default, {nn.addr for nn in self._region.graph})

        r = self._make_switch_cases_core(
            node,
            index_expr,
            cases,
            None,
            None,
            last_stmt.tags["ins_addr"],
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
        cmp_expr, cmp_lb, _cmp_ub = cmp  # pylint:disable=unused-variable

        if isinstance(last_stmt.false_target, Const):
            default_addr = last_stmt.false_target.value
            assert isinstance(default_addr, int)
        else:
            return False

        graph = graph_raw.filtered()
        full_graph = full_graph_raw.filtered()

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

        graph = graph_raw.filtered()
        full_graph = full_graph_raw.filtered()

        successors = list(graph.successors(node))

        jump_table = self.jump_tables[node.addr]
        assert jump_table.jumptable_entries is not None

        if successors and all(graph.in_degree[succ] == 1 for succ in successors):
            succ_addrs = {succ.addr for succ in successors}
            expected_entry_addrs = set(jump_table.jumptable_entries)
            # test if we have found all entries or all but one entry (where the one missing entry is likely the default
            # case).
            if succ_addrs == expected_entry_addrs or (
                succ_addrs.issubset(expected_entry_addrs) and len(expected_entry_addrs - succ_addrs) == 1
            ):
                # ensure that the successors have been properly structured, which means they either do not have
                # successors or they have one successor that is the likely default node of the switch-case construct
                # or the head of the switch-case construct (in which case, it's a loop).
                out_nodes = set()
                for succ in successors:
                    out_nodes |= {
                        succ for succ in full_graph.successors(succ) if succ is not node and succ not in successors
                    }
                out_nodes = list(out_nodes)
                if (
                    len(out_nodes) == 0
                    or (
                        len(out_nodes) == 1
                        and (
                            self._is_switch_case_address_loaded_from_memory_default_node(full_graph, out_nodes[0])
                            or self._is_switch_cases_address_loaded_from_memory_head(full_graph, out_nodes[0])
                        )
                    )
                ) and node.addr not in self._matched_incomplete_switch_case_addrs:
                    self._matched_incomplete_switch_case_addrs.add(node.addr)
                    new_node = IncompleteSwitchCaseNode(node.addr, node, successors)
                    self.replace_nodes_both(node, new_node)
                    for succ_node in successors:
                        self._region.remove_node(succ_node, absorbed_into=new_node)
                    if out_nodes:
                        self._region.add_edge(new_node, out_nodes[0])
                    self._graph_helper.replace_node(node, new_node)
                    return True
        return False

    def _switch_build_cases(
        self,
        case_and_entryaddrs: dict[int, int | tuple[int, int | None]],
        head_node,
        node_a: BaseNode,
        node_b_addr: int | None,
        graph_raw: networkx.DiGraph,
    ) -> tuple[OrderedDict, Any, set[Any]]:
        cases: OrderedDict[int | tuple[int, ...], SequenceNode] = OrderedDict()
        to_remove = set()

        graph = graph_raw.filtered()

        default_node_candidates = (
            [nn for nn in graph.nodes if nn.addr == node_b_addr] if node_b_addr is not None else []
        )
        node_default = (
            self._switch_find_default_node(graph, head_node, node_b_addr) if node_b_addr is not None else None
        )
        if node_default is not None and not isinstance(node_default, SequenceNode):
            # make the default node a SequenceNode so that we can insert Break and Continue nodes into it later
            new_node = SequenceNode(node_default.addr, nodes=[node_default])
            self.replace_nodes_both(node_default, new_node)
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
                            self.ail_manager.next_atom(),
                            Const(self.ail_manager.next_atom(), entry_addr, self.project.arch.bits),
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

        edge_marked = getattr(full_graph, "edge_marked", None)
        for nn in to_remove:
            if nn is head or (node_a is not None and nn is node_a):
                continue
            for src in graph.predecessors(nn):
                if src not in to_remove:
                    other_nodes_inedges.append((src, nn))
            for dst in full_graph.successors(nn):
                if dst not in to_remove:
                    if edge_marked is not None and edge_marked(nn, dst):
                        # cyclic refinement already turned this edge into a break inside the case node; it is not
                        # an unresolved out-edge of the switch and must not pick the switch's successor (or block
                        # the construction via the convergence checks below)
                        continue
                    out_edges.append((nn, dst))

        if bail_on_nonhead_outedges:
            nonhead_out_nodes = {edge[1] for edge in out_edges if edge[1] is not head}
            if len(nonhead_out_nodes) > 1:
                # not ready to be structured yet - do it later
                return False

        # check if structuring will create any dangling nodes. a successor whose only predecessors are absorbed
        # case nodes is not dangling when it is the switch's unique successor: the construction below re-attaches
        # it via the scnode -> out_dst_succ edge.
        unique_out_target = None
        nonhead_out_targets = {dst for _, dst in out_edges if dst is not head}
        if len(nonhead_out_targets) == 1:
            unique_out_target = next(iter(nonhead_out_targets))
        for case_node in to_remove:
            if case_node is not node_default and case_node is not node_a and case_node is not head:
                for succ in graph.successors(case_node):
                    if (
                        succ is not case_node
                        and succ is not head
                        and succ is not self._region.head
                        and succ is not unique_out_target
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
                        self.ail_manager.next_atom(),
                        Const(self.ail_manager.next_atom(), head.addr, self.project.arch.bits),
                        None,
                        ins_addr=out_src.addr,
                    )
                    jump_node = Block(out_src.addr, 0, statements=[jump_stmt])
                    case_node.nodes.append(jump_node)

            # out_dst_succ is the successor within the current region
            # out_dst_succ_fullgraph is the successor outside the current region
            if out_edges_to_head:
                # add an edge from SwitchCaseNode to head so that a loop will be structured later
                out_dst_succ = head
                out_dst_succ_fullgraph = None
            else:
                # add an edge from SwitchCaseNode to its most immediate successor (if there is one)
                # there might be an in-region successor and an out-of-region successor (especially due to the
                # introduction of self.dowhile_known_tail_nodes)!
                # example: 7995a0325b446c462bdb6ae10b692eee2ecadd8e888e9d7729befe4412007afb, function 1400EF820
                out_dst_succs = []
                out_dst_succs_fullgraph = []
                for _, o in other_out_edges:
                    if o in graph:
                        if o not in out_dst_succs:
                            out_dst_succs.append(o)
                    elif o in full_graph:
                        if o not in out_dst_succs_fullgraph:
                            out_dst_succs_fullgraph.append(o)
                out_dst_succ = sorted(out_dst_succs, key=lambda o: o.addr)[0] if out_dst_succs else None
                out_dst_succ_fullgraph = (
                    sorted(out_dst_succs_fullgraph, key=lambda o: o.addr)[0] if out_dst_succs_fullgraph else None
                )
                if len(out_dst_succs) > 1:
                    if self.dowhile_known_tail_nodes:
                        assert out_dst_succ is not None
                        l.warning(
                            "Multiple in-region successors detected for switch-case node at %#x. Picking %#x as the "
                            "successor and dropping others.",
                            scnode.addr,
                            out_dst_succ.addr,
                        )
                    else:
                        return False
                if len(out_dst_succs_fullgraph) > 1:
                    assert out_dst_succ_fullgraph is not None
                    l.warning(
                        "Multiple out-of-region successors detected for switch-case node at %#x. Picking %#x as the "
                        "successor and dropping others.",
                        scnode.addr,
                        out_dst_succ_fullgraph.addr,
                    )

            if out_dst_succ is not None:
                self._region.add_edge(scnode, out_dst_succ)
                if full_graph.has_edge(head, out_dst_succ):
                    self._region.remove_edge_with_successors_only(head, out_dst_succ)
            if out_dst_succ_fullgraph is not None:
                self._region.add_edge(scnode, out_dst_succ_fullgraph)
                if full_graph.has_edge(head, out_dst_succ_fullgraph):
                    self._region.remove_edge_with_successors_only(head, out_dst_succ_fullgraph)

            # fix full_graph if needed: remove successors that are no longer needed
            for _out_src, out_dst in other_out_edges:
                if (
                    out_dst is not out_dst_succ
                    and out_dst in full_graph
                    and out_dst not in graph
                    and full_graph.in_degree[out_dst] == 0
                ):
                    self._region.remove_node(out_dst)

        if node_default is not None:
            # the head no longer goes to the default case
            self._region.detach_edge(head, node_default)
        elif node_default_addr is not None:
            # the default node is not in the current graph, but it might be in the full graph
            node_default_in_full_graph = next(iter(nn for nn in full_graph if nn.addr == node_default_addr), None)
            if node_default_in_full_graph is not None and full_graph.has_edge(head, node_default_in_full_graph):
                # the head no longer jumps to the default node - the switch jumps to it
                self._region.hide_edge(head, node_default_in_full_graph)

        self._region.add_edge(head, scnode)
        for nn in to_remove:
            self._region.remove_node(nn, absorbed_into=scnode)

        self._graph_helper.add_node_successor(head, scnode)

        # the head's own out-of-region case targets (e.g., the region successor when a case continues to the
        # enclosing loop head) are represented as goto-cases inside scnode, but the head's direct edges to them
        # remain and would prevent the head+scnode chain from ever collapsing. shift those edges onto the switch
        # node, mirroring the out_dst_succ handling above.
        for t in list(full_graph.successors(head)):
            if t is scnode or t in graph or (node_a is not None and t is node_a):
                continue
            self._region.remove_edge_with_successors_only(head, t)
            if not full_graph.has_edge(scnode, t):
                self._region.add_edge(scnode, t)

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

    def _find_unstructured_switch_case_dispatch_nodes(self, graph) -> set[Block | BaseNode]:
        """
        Return a set of nodes that are unstructured switch-case dispatch nodes.
        """
        if not self.jump_tables:
            return set()
        switch_case_dispatch_nodes = set()
        for node in graph:
            if node.addr in self.jump_tables:
                # maybe it has been structured?
                try:
                    last_stmts = self.cond_proc.get_last_statements(node)
                except EmptyBlockNotice:
                    continue
                if (
                    len(last_stmts) == 1
                    and isinstance(last_stmts[0], Jump)
                    and not isinstance(last_stmts[0].target, Const)
                ):
                    switch_case_dispatch_nodes.add(node)

        return switch_case_dispatch_nodes

    def _build_switch_case_check_cache(self, graph) -> None:
        """
        Build a cache for switch-case-related checks; used by the following methods:
        - _is_node_unstructured_switch_case_head
        - _is_switch_cases_address_loaded_from_memory_head
        """

        switch_case_heads: set[Block | BaseNode] = set()
        switch_case_dispatch_nodes = self._find_unstructured_switch_case_dispatch_nodes(graph)
        for node in switch_case_dispatch_nodes:
            preds = list(graph.predecessors(node))
            if len(preds) == 1:
                pred = preds[0]
                # two situations:
                # A. pred is switch-case head: pred has two successors: one is the dispatch node, the other is the default case node
                # B. pred has a predecessor that is a switch-case head: pred has exactly one successor
                switch_case_heads.add(pred)
                if graph.out_degree[pred] == 1:
                    # case B: step back to find the switch-case head
                    pred_pred = list(graph.predecessors(pred))
                    if len(pred_pred) == 1 and pred_pred[0] is not pred:
                        switch_case_heads.add(pred_pred[0])

        self._unstructured_switch_case_heads_and_dispatch_nodes = switch_case_heads | set(switch_case_dispatch_nodes)

    def _is_node_unstructured_switch_case_head_or_dispatch_node(self, graph, node) -> bool:
        if self._unstructured_switch_case_heads_and_dispatch_nodes is None:
            # build cache
            self._build_switch_case_check_cache(graph)
        return node in self._unstructured_switch_case_heads_and_dispatch_nodes

    def _is_switch_cases_address_loaded_from_memory_head(self, graph, node) -> bool:
        if self._unstructured_switch_case_heads_and_dispatch_nodes is None:
            # build cache
            self._build_switch_case_check_cache(graph)
        return node in self._unstructured_switch_case_heads_and_dispatch_nodes or node in self.switch_case_known_heads

    def _is_switch_cases_address_loaded_from_memory_head_or_jumpnode(self, graph, node) -> bool:
        if self._unstructured_switch_case_heads_and_dispatch_nodes is None:
            # build cache
            self._build_switch_case_check_cache(graph)
        if node in self._unstructured_switch_case_heads_and_dispatch_nodes or node in self.switch_case_known_heads:
            return True
        return isinstance(node, IncompleteSwitchCaseNode)

    def _is_switch_case_address_loaded_from_memory_default_node(self, graph, node) -> bool:
        # the default node should have a predecessor that is a switch-case head node
        for pred in graph.predecessors(node):
            if self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(graph, pred):
                return True
        return False

    # other acyclic schemas

    def _match_acyclic_sequence(self, graph_raw, full_graph_raw, start_node) -> bool:
        """
        Check if there is a sequence of regions, where each region has a single predecessor and a single successor.
        """

        full_graph = full_graph_raw.filtered()
        graph = graph_raw.filtered()

        if graph.out_degree[start_node] != 1 or full_graph.out_degree[start_node] != 1:
            return False
        end_node = next(iter(graph.successors(start_node)))
        if (
            full_graph.in_degree[end_node] == 1
            and not full_graph.has_edge(end_node, start_node)
            and not self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, start_node)
            and end_node not in self.dowhile_known_tail_nodes
        ):
            new_seq = None
            if not self._is_switch_cases_address_loaded_from_memory_head_or_jumpnode(full_graph, end_node):
                # merge two blocks
                new_seq = self._merge_nodes(start_node, end_node)
            elif isinstance(end_node, IncompleteSwitchCaseNode):
                # a special case where there is a node between the actual switch-case head and the jump table
                # head
                # binary 7995a0325b446c462bdb6ae10b692eee2ecadd8e888e9d7729befe4412007afb, function 0x1400326C0
                # keep the IncompleteSwitchCaseNode, and merge two blocks into the head of the IncompleteSwitchCaseNode.
                new_seq = self._merge_nodes(start_node, end_node.head)
                new_seq.addr = end_node.addr
                end_node.head = new_seq
                new_seq = end_node

            if new_seq is not None:
                self.replace_nodes_both(start_node, new_seq, old_node_1=end_node)
                return True
        return False

    def _match_acyclic_ite(self, graph_raw, full_graph_raw, start_node) -> bool:
        """
        Check if start_node is the beginning of an If-Then-Else region. Create a Condition node if it is the case.
        """

        full_graph = full_graph_raw.filtered()
        graph = graph_raw.filtered()

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
                    and not self._is_node_unstructured_switch_case_head_or_dispatch_node(full_graph, left)
                    and not self._is_node_unstructured_switch_case_head_or_dispatch_node(full_graph, right)
                ):
                    if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, right):
                        # c = !c
                        edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                        last_if_jump = self._remove_last_statement_if_jump(start_node)
                        new_cond_node = ConditionNode(
                            last_if_jump.tags["ins_addr"] if last_if_jump is not None else start_node.addr,
                            None,
                            edge_cond_left,
                            left,
                            false_node=right,
                        )
                        new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                        if not left_succs:
                            self.replace_nodes_both(start_node, new_node, old_node_1=right)
                            self._region.remove_node(left, absorbed_into=new_node, absorb_out_edges=True)
                        else:
                            self.replace_nodes_both(start_node, new_node, old_node_1=left)
                            self._region.remove_node(right, absorbed_into=new_node, absorb_out_edges=True)

                        return True

            if right in graph and not right_succs and full_graph.in_degree[right] == 1 and left in graph:
                # swap them
                left, right = right, left
                left_succs, right_succs = right_succs, left_succs
            if left in graph and not left_succs and full_graph.in_degree[left] == 1 and right in graph:
                # potentially If-Then
                if not self._is_node_unstructured_switch_case_head_or_dispatch_node(
                    full_graph, left
                ) and not self._is_node_unstructured_switch_case_head_or_dispatch_node(full_graph, right):
                    if self.cond_proc.have_opposite_edge_conditions(full_graph, start_node, left, right):
                        # c = !c
                        edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                        last_if_jump = self._remove_last_statement_if_jump(start_node)
                        new_cond_node = ConditionNode(
                            last_if_jump.tags["ins_addr"] if last_if_jump is not None else start_node.addr,
                            None,
                            edge_cond_left,
                            left,
                            false_node=None,
                        )
                        new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                        self.replace_nodes_both(start_node, new_node, old_node_1=left)

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
                        last_if_jump.tags["ins_addr"] if last_if_jump is not None else start_node.addr,
                        None,
                        edge_cond_left,
                        left,
                        false_node=None,
                    )
                    new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                    self.replace_nodes_both(start_node, new_node, old_node_1=left)

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
                        last_stmt.tags["ins_addr"] if last_stmt is not None else start_node.addr,
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
                                    self.ail_manager.next_atom(),
                                    Const(self.ail_manager.next_atom(), right.addr, self.project.arch.bits),
                                    ins_addr=new_cond_node.addr,
                                )
                            ],
                        )
                        new_nodes.append(new_jump_node)
                    new_node = SequenceNode(start_node.addr, nodes=new_nodes)

                    self.replace_nodes_both(start_node, new_node, old_node_1=left)

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

        graph = graph_raw.filtered()
        full_graph = full_graph_raw.filtered()

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
            left_cond_expr_neg = UnaryOp(self.ail_manager.next_atom(), "Not", left_cond_expr, ins_addr=start_node.addr)
            left_right_cond_expr = self.cond_proc.convert_claripy_bool_ast(left_right_cond)
            if not self._is_single_statement_block(left):
                if not self._should_use_multistmtexprs(left):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(left)
                assert stmts is not None
                left_right_cond_expr = MultiStatementExpression(
                    self.ail_manager.next_atom(), stmts, left_right_cond_expr, ins_addr=left.addr
                )
            cond = BinaryOp(
                self.ail_manager.next_atom(),
                "LogicalOr",
                [left_cond_expr_neg, left_right_cond_expr],
                ins_addr=start_node.addr,
            )
            cond_jump = ConditionalJump(
                self.ail_manager.next_atom(),
                cond,
                Const(self.ail_manager.next_atom(), right.addr, self.project.arch.bits),
                Const(self.ail_manager.next_atom(), succ.addr, self.project.arch.bits),
                true_target_idx=right.idx if isinstance(right, (Block, MultiNode)) else None,
                false_target_idx=succ.idx if isinstance(succ, (Block, MultiNode)) else None,
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes_both(start_node, new_node, old_node_1=left)

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
                right_left_cond_expr = MultiStatementExpression(
                    self.ail_manager.next_atom(), stmts, right_left_cond_expr, ins_addr=left.addr
                )
            cond = BinaryOp(
                self.ail_manager.next_atom(),
                "LogicalOr",
                [left_cond_expr, right_left_cond_expr],
                ins_addr=start_node.addr,
            )
            cond_jump = ConditionalJump(
                self.ail_manager.next_atom(),
                cond,
                Const(self.ail_manager.next_atom(), left.addr, self.project.arch.bits, ins_addr=start_node.addr),
                Const(self.ail_manager.next_atom(), else_node.addr, self.project.arch.bits, ins_addr=start_node.addr),
                true_target_idx=left.idx if isinstance(left, (Block, MultiNode)) else None,
                false_target_idx=else_node.idx if isinstance(else_node, (Block, MultiNode)) else None,
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes_both(start_node, new_node, old_node_1=right)

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
                left_succ_cond_expr = MultiStatementExpression(
                    self.ail_manager.next_atom(), stmts, left_succ_cond_expr, ins_addr=left.addr
                )
            left_succ_cond_expr_neg = UnaryOp(
                self.ail_manager.next_atom(), "Not", left_succ_cond_expr, ins_addr=start_node.addr
            )
            cond = BinaryOp(
                self.ail_manager.next_atom(),
                "LogicalAnd",
                [left_cond_expr, left_succ_cond_expr_neg],
                ins_addr=start_node.addr,
            )
            cond_jump = ConditionalJump(
                self.ail_manager.next_atom(),
                cond,
                Const(self.ail_manager.next_atom(), right.addr, self.project.arch.bits),
                Const(self.ail_manager.next_atom(), succ.addr, self.project.arch.bits),
                true_target_idx=right.idx if isinstance(right, (Block, MultiNode)) else None,
                false_target_idx=succ.idx if isinstance(succ, (Block, MultiNode)) else None,
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes_both(start_node, new_node, old_node_1=left)
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
                left_right_cond_expr = MultiStatementExpression(
                    self.ail_manager.next_atom(), stmts, left_right_cond_expr, ins_addr=left.addr
                )
            cond = BinaryOp(
                self.ail_manager.next_atom(),
                "LogicalAnd",
                [left_cond_expr, left_right_cond_expr],
                ins_addr=start_node.addr,
            )
            cond_jump = ConditionalJump(
                self.ail_manager.next_atom(),
                cond,
                Const(self.ail_manager.next_atom(), right.addr, self.project.arch.bits),
                Const(self.ail_manager.next_atom(), else_node.addr, self.project.arch.bits),
                true_target_idx=right.idx if isinstance(right, (Block, MultiNode)) else None,
                false_target_idx=else_node.idx if isinstance(else_node, (Block, MultiNode)) else None,
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes_both(start_node, new_node, old_node_1=left)
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
                if graph_raw.filtered().has_edge(src, dst):
                    self._virtualize_edge(src, dst)
                    l.debug("last_resort: Removed edge %r -> %r (type 3)", src, dst)
                    return True

        # virtualize an edge to allow progressing in structuring
        all_edges_wo_dominance = []  # to ensure determinism, edges in this list are ordered by a tuple of
        # (src_addr, dst_addr)
        secondary_edges = []  # likewise, edges in this list are ordered by a tuple of (src_addr, dst_addr)
        other_edges = []

        full_graph = full_graph_raw.filtered()
        graph = graph_raw.filtered()

        idoms = networkx.immediate_dominators(full_graph, head)
        # acyclic_graph is read-only here (edges, in_degree, has_edge, iteration), so use a zero-copy overlay view
        # instead of materializing the whole region graph on every last-resort attempt.
        if networkx.is_directed_acyclic_graph(full_graph):
            acyclic_graph = full_graph
        else:
            acyclic_graph = self._graph_helper.to_acyclic_by_order(full_graph)
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

        # acyclic_graph may contain more than one entry node. Cover every entry in the post-order without mutating the
        # graph (it is a zero-copy overlay view) via a deterministic multi-source DFS seeded with all entries -- this
        # reproduces the old synthetic-head traversal (entries visited in _sort_node order) with no temporary node.
        graph_entries = [nn for nn in acyclic_graph if acyclic_graph.in_degree[nn] == 0]
        if len(graph_entries) > 1:
            ordered_nodes = list(
                reversed(list(GraphUtils.dfs_postorder_nodes_deterministic_multi(acyclic_graph, graph_entries)))
            )
        else:
            ordered_nodes = list(reversed(list(GraphUtils.dfs_postorder_nodes_deterministic(acyclic_graph, head))))
        node_seq = {nn: (len(ordered_nodes) - idx) for (idx, nn) in enumerate(ordered_nodes)}  # post-order
        if len(node_seq) < len(acyclic_graph):
            # some nodes are not reachable from head - add them to node_seq as well
            # but this is usually the result of incorrect structuring, so we may still fail at a later point
            l.warning("Adding %d unreachable nodes to node_seq", len(acyclic_graph) - len(node_seq))
            unreachable_nodes = sorted(
                (nn for nn in acyclic_graph if nn not in node_seq),
                key=lambda n: (n.addr, (-1 if n.idx is None else n.idx) if hasattr(n, "idx") else 0),
            )
            max_seq = max(node_seq.values(), default=0)
            for i, nn in enumerate(unreachable_nodes):
                node_seq[nn] = max_seq + i

        if all_edges_wo_dominance:
            all_edges_wo_dominance = self._order_virtualizable_edges(full_graph, all_edges_wo_dominance, node_seq)
            # virtualize the first edge
            src, dst = all_edges_wo_dominance[0]
            self._virtualize_edge(src, dst)
            l.debug("last_resort: Removed edge %r -> %r (type 1)", src, dst)
            return True

        if secondary_edges:
            secondary_edges = self._order_virtualizable_edges(full_graph, secondary_edges, node_seq)
            # virtualize the first edge
            src, dst = secondary_edges[0]
            self._virtualize_edge(src, dst)
            l.debug("last_resort: Removed edge %r -> %r (type 2)", src, dst)
            return True

        if (
            self._region.parent is None
            and not self._region.cyclic
            and not networkx.is_directed_acyclic_graph(full_graph)
        ):
            # an acyclic region must not contain cycles; one can appear as debris when an inner cyclic region
            # fails to structure and dissolves its partially-refined body into this region. the cycle-closing
            # edges are excluded from the candidate lists above (to_acyclic_by_order dropped them from
            # acyclic_graph), so without this fallback the region can never become structurable. only the root
            # region recovers this way (a goto): anywhere else, failing and dissolving into an enclosing region
            # gives a cyclic ancestor the chance to structure the loop properly first.
            # virtualize one cycle edge to recover.
            cycle_edges = []
            for src, dst in full_graph.edges:
                if src is dst or acyclic_graph.has_edge(src, dst) or src not in graph:
                    continue
                if (
                    isinstance(src, Block)
                    and src.statements
                    and isinstance(src.statements[-1], IncompleteSwitchCaseHeadStatement)
                ):
                    continue
                cycle_edges.append((src, dst))
            if cycle_edges:
                cycle_edges = sorted(cycle_edges, key=lambda edge: (edge[0].addr, edge[1].addr))
                src, dst = cycle_edges[0]
                self._virtualize_edge(src, dst)
                l.debug("last_resort: Removed cycle edge %r -> %r in an acyclic region (type 4)", src, dst)
                return True

        l.debug("last_resort: No edge to remove")
        return False

    def _virtualize_edge(self, src, dst):
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
                goto0_condition = UnaryOp(self.ail_manager.next_atom(), "Not", last_stmt.condition)
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
                    last_stmt.tags["ins_addr"],
                    0,
                    statements=[
                        Jump(
                            self.ail_manager.next_atom(), goto0_target, ins_addr=last_stmt.tags["ins_addr"], stmt_idx=0
                        )
                    ],
                )
                cond_node = ConditionNode(last_stmt.tags["ins_addr"], None, goto0_condition, goto0)
                goto1_node = Block(
                    last_stmt.tags["ins_addr"],
                    0,
                    statements=[
                        Jump(
                            self.ail_manager.next_atom(), goto1_target, ins_addr=last_stmt.tags["ins_addr"], stmt_idx=0
                        )
                    ],
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
                    Jump(
                        self.ail_manager.next_atom(),
                        Const(self.ail_manager.next_atom(), dst.addr, self.project.arch.bits),
                        ins_addr=stmt_addr,
                        stmt_idx=0,
                    )
                ],
            )
            new_src = SequenceNode(src.addr, nodes=[src, goto_node])

        self.virtualized_edges.add((src, dst))
        self._region.detach_edge(src, dst)
        if new_src is not None:
            self.replace_nodes_both(src, new_src)
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
        enter_loops=True,
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

        def _handle_Loop(loop_node: LoopNode, parent=None, **kwargs):  # pylint:disable=unused-argument
            if enter_loops:
                walker._handle_Loop(loop_node, parent=parent, **kwargs)  # pylint:disable=protected-access

        walker = SequenceWalker(
            handlers={
                Block: _handle_Block,
                MultiNode: _handle_MultiNode,
                BreakNode: _handle_BreakNode,
                ConditionNode: _handle_ConditionNode,
                LoopNode: _handle_Loop,
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

    def _unpack_sequencenode_head_overlay(self, seq: SequenceNode):
        if not seq.nodes:
            return False, None
        node = seq.nodes[0]
        new_seq = seq.copy()
        new_seq.nodes = new_seq.nodes[1:]
        if new_seq.nodes:
            new_seq.addr = new_seq.nodes[0].addr

        region: RegionOverlay = self._region
        gws = region.graph_with_successors
        preds = list(gws.predecessors(seq))
        succs = list(gws.successors(seq))
        region.add_node(node)
        region.remove_node(seq, absorbed_into=node)
        for pred in preds:
            region.add_edge(pred, node)
        if new_seq.nodes:
            region.add_edge(node, new_seq)
        for succ in succs:
            if succ is seq:
                region.add_edge(new_seq, new_seq)
            else:
                region.add_edge(new_seq, succ)
        return True, new_seq

    def _unpack_incompleteswitchcasenode_overlay(
        self, incscnode: IncompleteSwitchCaseNode, jumptable_entries: list[int]
    ) -> bool:
        region: RegionOverlay = self._region
        graph = region.graph
        gws = region.graph_with_successors
        # gate on the member view, matching the original member-graph unpacking
        member_non_case_succs = [succ for succ in graph.successors(incscnode) if succ.addr not in jumptable_entries]
        if len(member_non_case_succs) > 1:
            return False
        preds = list(gws.predecessors(incscnode))
        succs = list(gws.successors(incscnode))
        non_case_succs = [succ for succ in succs if succ.addr not in jumptable_entries]
        region.add_node(incscnode.head)
        region.remove_node(incscnode, absorbed_into=incscnode.head)
        for pred in preds:
            region.add_edge(pred, incscnode.head)
        for succ in succs:
            if succ not in non_case_succs:
                region.add_edge(incscnode.head, succ)
        for case_node in incscnode.cases:
            region.add_edge(incscnode.head, case_node)
            if non_case_succs:
                region.add_edge(case_node, non_case_succs[0])
        return True

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

    def replace_nodes_both(
        self,
        old_node_0,
        new_node,
        old_node_1=None,
        self_loop=True,
        drop_refinement_marks: bool = False,
    ):
        """
        Replace one or two nodes with a new node in the region: the member view, the with-successors view, and
        the shared graph are all updated by the single overlay operation. If ``old_node_1`` is a successor of the
        region rather than a member, it is absorbed into the new node in this region's views only.
        """
        region: RegionOverlay = self._region
        member_old_1 = old_node_1 if old_node_1 is None or old_node_1 in region.graph else None
        region.replace_nodes(old_node_0, new_node, old_node_1=member_old_1, self_loop=self_loop)
        if old_node_1 is not None and member_old_1 is None:
            # the absorbed node is a successor of the region
            region.absorb_successor_into(old_node_1, new_node)
        if drop_refinement_marks:
            region.drop_edge_marks_from(new_node, "cyclic_refinement_outgoing")

        if old_node_1 is not None:
            self._graph_helper.replace_nodes(old_node_0, old_node_1, new_node)
        else:
            self._graph_helper.replace_node(old_node_0, new_node)

    def _remove_edges_except_overlay(self, src, dst) -> None:
        """
        Remove all out-edges of a member node except the one to ``dst``: edges to fellow members are removed for
        real, while edges to region successors are only removed from this region's views (enclosing regions keep
        them, as they always have).
        """
        region: RegionOverlay = self._region
        graph = region.graph
        gws = region.graph_with_successors
        for succ in list(gws.successors(src)):
            if succ is not src and succ is not dst:
                if succ in graph:
                    region.detach_edge(src, succ)
                else:
                    region.hide_edge(src, succ)

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
