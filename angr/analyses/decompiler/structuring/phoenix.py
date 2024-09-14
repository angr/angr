# pylint:disable=line-too-long,import-outside-toplevel,import-error,multiple-statements,too-many-boolean-expressions
from __future__ import annotations
from typing import Any, TYPE_CHECKING
from collections import defaultdict, OrderedDict
from enum import Enum
import logging

import networkx

import claripy
from ailment.block import Block
from ailment.statement import Statement, ConditionalJump, Jump, Label, Return
from ailment.expression import Const, UnaryOp, MultiStatementExpression

from angr.utils.graph import GraphUtils
from angr.utils.ail import is_phi_assignment
from ....knowledge_plugins.cfg import IndirectJumpType
from ....utils.constants import SWITCH_MISSING_DEFAULT_NODE_ADDR
from ....utils.graph import dominates, to_acyclic_graph, dfs_back_edges
from ..sequence_walker import SequenceWalker
from ..utils import (
    remove_last_statement,
    extract_jump_targets,
    switch_extract_cmp_bounds,
    is_empty_or_label_only_node,
    has_nonlabel_nonphi_statements,
    first_nonlabel_nonphi_statement,
)
from ..counters.call_counter import AILCallCounter
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
        self.switch_case_known_heads: set[Block] = set()

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

        self._use_multistmtexprs = use_multistmtexprs
        self._analyze()

    @staticmethod
    def _assert_graph_ok(g, msg: str) -> None:
        if _DEBUG:
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
                self._region = pre_refinement_region

            self.result = None  # the actual result is in self._region.graph and self._region.graph_with_successors

    def _analyze_cyclic(self) -> bool:
        any_matches = False
        acyclic_graph = to_acyclic_graph(self._region.graph, loop_heads=[self._region.head])
        for node in list(reversed(GraphUtils.quasi_topological_sort_nodes(acyclic_graph))):
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
            self._assert_graph_ok(self._region.graph, "Removed incorrect edges")
        return any_matches

    def _match_cyclic_schemas(self, node, head, graph, full_graph) -> bool:
        matched, loop_node, successor_node = self._match_cyclic_while(node, head, graph, full_graph)
        if matched:
            # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
            self._rewrite_conditional_jumps_to_breaks(loop_node.sequence_node, [successor_node.addr])
            # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
            self._rewrite_jumps_to_continues(loop_node.sequence_node)
            return True

        matched, loop_node, successor_node = self._match_cyclic_dowhile(node, head, graph, full_graph)
        if matched:
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
                # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
                self._rewrite_conditional_jumps_to_breaks(loop_node.sequence_node, [successor_node.addr])
                # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
                self._rewrite_jumps_to_continues(loop_node.sequence_node)
                return True

        matched, loop_node = self._match_cyclic_natural_loop(node, head, graph, full_graph)
        if matched:
            if self._region.successors is not None and len(self._region.successors) == 1:
                # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
                self._rewrite_conditional_jumps_to_breaks(
                    loop_node.sequence_node, [succ.addr for succ in self._region.successors]
                )
            # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
            self._rewrite_jumps_to_continues(loop_node.sequence_node)
        return matched

    def _match_cyclic_while(self, node, head, graph, full_graph) -> tuple[bool, LoopNode | None, BaseNode | None]:
        succs = list(full_graph.successors(node))
        if len(succs) == 2:
            left, right = succs

            if full_graph.has_edge(right, node) and not full_graph.has_edge(left, node):
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
                    and isinstance(first_nonlabel_nonphi_statement(head_block.nodes[0]), ConditionalJump)
                    or isinstance(head_block, Block)
                    and head_block.statements
                    and isinstance(first_nonlabel_nonphi_statement(head_block), ConditionalJump)
                ):
                    # it's a while loop if the conditional jump (or the head block) is at the beginning of node
                    loop_type = "while" if head_block_idx == 0 else "do-while"
                    # otherwise it's a do-while loop
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, head_block, left)
                    edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, head_block, right)
                    if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                        # c = !c
                        if head_block_idx == 0:
                            self._remove_first_statement_if_jump(head_block)
                        else:
                            remove_last_statement(head_block)
                        seq_node = SequenceNode(node.addr, nodes=[node]) if not isinstance(node, SequenceNode) else node
                        loop_node = LoopNode(loop_type, edge_cond_left, seq_node, addr=seq_node.addr)
                        self.replace_nodes(graph, node, loop_node, self_loop=False)
                        self.replace_nodes(full_graph, node, loop_node, self_loop=False)

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except(graph, loop_node, right)
                        self._remove_edges_except(full_graph, loop_node, right)

                        return True, loop_node, right
            elif (
                full_graph.has_edge(left, node)
                and left is not head
                and full_graph.in_degree[left] == 1
                and full_graph.out_degree[left] == 1
                and not full_graph.has_edge(right, node)
            ):
                # possible candidate
                _, _, head_block = self._find_node_going_to_dst(node, left, condjump_only=True)
                if head_block is not None:
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, head_block, left)
                    edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, head_block, right)
                    if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                        # c = !c
                        if PhoenixStructurer._is_single_statement_block(node):
                            # the single-statement-block check is to ensure we don't execute any code before the
                            # conditional jump. this way the entire node can be dropped.
                            new_node = SequenceNode(node.addr, nodes=[left])
                            loop_node = LoopNode("while", edge_cond_left, new_node, addr=node.addr)

                            # on the original graph
                            self.replace_nodes(graph, node, loop_node, old_node_1=left, self_loop=False)
                            # on the graph with successors
                            self.replace_nodes(full_graph, node, loop_node, old_node_1=left, self_loop=False)

                            # ensure the loop has only one successor: the right node
                            self._remove_edges_except(graph, loop_node, right)
                            self._remove_edges_except(full_graph, loop_node, right)

                            return True, loop_node, right
                        # we generate a while-true loop instead
                        last_stmt = self._remove_last_statement_if_jump(head_block)
                        cond_jump = Jump(
                            None,
                            Const(None, None, right.addr, self.project.arch.bits),
                            None,
                            ins_addr=last_stmt.ins_addr,
                        )
                        jump_node = Block(last_stmt.ins_addr, None, statements=[cond_jump])
                        cond_jump_node = ConditionNode(last_stmt.ins_addr, None, edge_cond_right, jump_node)
                        new_node = SequenceNode(node.addr, nodes=[node, cond_jump_node, left])
                        loop_node = LoopNode("while", claripy.true, new_node, addr=node.addr)

                        # on the original graph
                        self.replace_nodes(graph, node, loop_node, old_node_1=left, self_loop=False)
                        # on the graph with successors
                        self.replace_nodes(full_graph, node, loop_node, old_node_1=left, self_loop=False)

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except(graph, loop_node, right)
                        self._remove_edges_except(full_graph, loop_node, right)

                        return True, loop_node, right

                if self._improve_algorithm and full_graph.out_degree[node] == 1:
                    # while (true) { ...; if (...) break; }
                    _, _, head_block = self._find_node_going_to_dst(node, left, condjump_only=True)
                    if head_block is not None:
                        edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, head_block, left)
                        edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, head_block, right)
                        if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                            # c = !c
                            self._remove_last_statement_if_jump(head_block)
                            cond_break = ConditionalBreakNode(node.addr, edge_cond_right, right.addr)
                            new_node = SequenceNode(node.addr, nodes=[node, cond_break, left])
                            loop_node = LoopNode("while", claripy.true, new_node, addr=node.addr)

                            # on the original graph
                            self.replace_nodes(graph, node, loop_node, old_node_1=left, self_loop=False)
                            # on the graph with successors
                            self.replace_nodes(full_graph, node, loop_node, old_node_1=left, self_loop=False)

                            # ensure the loop has only one successor: the right node
                            self._remove_edges_except(graph, loop_node, right)
                            self._remove_edges_except(full_graph, loop_node, right)

                            return True, loop_node, right

        return False, None, None

    def _match_cyclic_while_with_single_successor(
        self, node, head, graph, full_graph
    ) -> tuple[bool, LoopNode | None, BaseNode | None]:
        if self._region.successors:
            return False, None, None
        if node is not head:
            return False, None, None

        if not (node is head or graph.in_degree[node] == 2):
            return False, None, None

        loop_cond = None
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
            successor_node = node.nodes[-1].true_node
            # test if the successor_node returns or not
            # FIXME: It might be too strict
            try:
                last_stmt = self.cond_proc.get_last_statement(successor_node)
            except EmptyBlockNotice:
                last_stmt = None
            if last_stmt is not None and isinstance(last_stmt, Return):
                loop_cond = claripy.Not(node.nodes[-1].condition)

        if loop_cond is None:
            return False, None, None

        node_copy = node.copy()
        node_copy.nodes[-1] = node_copy.nodes[-1].false_node  # replace the last node with the false node
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
                graph.remove_node(node_)
        self.replace_nodes(graph, node, loop_node, self_loop=False)
        graph.add_edge(loop_node, successor_node)

        # on the graph with successors
        for node_ in seq_node.nodes:
            if node_ is not node_copy:
                full_graph.remove_node(node_)
        self.replace_nodes(full_graph, node, loop_node, self_loop=False)
        full_graph.add_edge(loop_node, successor_node)

        return True, loop_node, successor_node

    def _match_cyclic_dowhile(self, node, head, graph, full_graph) -> tuple[bool, LoopNode | None, BaseNode | None]:
        preds = list(full_graph.predecessors(node))
        succs = list(full_graph.successors(node))
        if ((node is head and len(preds) >= 1) or len(preds) >= 2) and len(succs) == 1:
            succ = succs[0]
            succ_preds = list(full_graph.predecessors(succ))
            succ_succs = list(full_graph.successors(succ))
            if head is not succ and len(succ_succs) == 2 and node in succ_succs and len(succ_preds) == 1:
                succ_succs.remove(node)
                out_node = succ_succs[0]

                if full_graph.has_edge(succ, node):
                    # possible candidate
                    _, _, succ_block = self._find_node_going_to_dst(succ, out_node, condjump_only=True)
                    if succ_block is not None:
                        edge_cond_succhead = self.cond_proc.recover_edge_condition(full_graph, succ_block, node)
                        edge_cond_succout = self.cond_proc.recover_edge_condition(full_graph, succ_block, out_node)
                        if claripy.is_true(claripy.Not(edge_cond_succhead) == edge_cond_succout):
                            # c = !c
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
                                if stmts:
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
                            self.replace_nodes(graph, node, loop_node, old_node_1=succ, self_loop=False)
                            # on the graph with successors
                            self.replace_nodes(full_graph, node, loop_node, old_node_1=succ, self_loop=False)

                            return True, loop_node, out_node
        elif ((node is head and len(preds) >= 1) or len(preds) >= 2) and len(succs) == 2 and node in succs:
            # head forms a self-loop
            succs.remove(node)
            succ = succs[0]
            if not full_graph.has_edge(succ, node):
                # possible candidate
                edge_cond_head = self.cond_proc.recover_edge_condition(full_graph, node, node)
                edge_cond_head_succ = self.cond_proc.recover_edge_condition(full_graph, node, succ)
                if claripy.is_true(claripy.Not(edge_cond_head) == edge_cond_head_succ):
                    # c = !c
                    self._remove_last_statement_if_jump(node)
                    seq_node = SequenceNode(node.addr, nodes=[node]) if not isinstance(node, SequenceNode) else node
                    loop_node = LoopNode("do-while", edge_cond_head, seq_node, addr=seq_node.addr)

                    # on the original graph
                    self.replace_nodes(graph, node, loop_node, self_loop=False)
                    # on the graph with successors
                    self.replace_nodes(full_graph, node, loop_node, self_loop=False)

                    return True, loop_node, succ
        return False, None, None

    def _match_cyclic_natural_loop(self, node, head, graph, full_graph) -> tuple[bool, LoopNode | None]:
        if not (node is head or graph.in_degree[node] == 2):
            return False, None

        # check if there is a cycle that starts with node and ends with node
        next_node = node
        seq_node = SequenceNode(node.addr, nodes=[node])
        seen_nodes = set()
        while True:
            succs = list(full_graph.successors(next_node))
            if len(succs) != 1:
                return False, None
            next_node = succs[0]

            if next_node is node:
                break
            if next_node is not node and next_node in seen_nodes:
                return False, None

            seen_nodes.add(next_node)
            seq_node.nodes.append(next_node)

        loop_node = LoopNode("while", claripy.true, seq_node, addr=node.addr)

        # on the original graph
        for node_ in seq_node.nodes:
            if node_ is not node:
                graph.remove_node(node_)
        self.replace_nodes(graph, node, loop_node, self_loop=False)

        # on the graph with successors
        for node_ in seq_node.nodes:
            if node_ is not node:
                full_graph.remove_node(node_)
        self.replace_nodes(full_graph, node, loop_node, self_loop=False)

        return True, loop_node

    def _refine_cyclic(self) -> bool:
        loop_heads = {t for _, t in dfs_back_edges(self._region.graph, self._region.head)}
        sorted_loop_heads = GraphUtils.quasi_topological_sort_nodes(self._region.graph, nodes=list(loop_heads))

        for head in sorted_loop_heads:
            l.debug("... refining cyclic at %r", head)
            refined = self._refine_cyclic_core(head)
            l.debug("... refined: %s", refined)
            if refined:
                return True
        return False

    def _refine_cyclic_core(self, loop_head) -> bool:
        graph: networkx.DiGraph = self._region.graph
        fullgraph: networkx.DiGraph = self._region.graph_with_successors
        if fullgraph is None:
            fullgraph = networkx.DiGraph(self._region.graph)

        # check if there is an out-going edge from the loop head
        head_succs = list(fullgraph.successors(loop_head))
        successor = None  # the loop successor
        loop_type = None
        # continue_node either the loop header for while(true) loops or the loop header predecessor for do-while loops
        continue_node = loop_head

        is_while, result_while = self._refine_cyclic_is_while_loop(graph, fullgraph, loop_head, head_succs)
        is_dowhile, result_dowhile = self._refine_cyclic_is_dowhile_loop(graph, fullgraph, loop_head, head_succs)

        continue_edges: list[tuple[BaseNode, BaseNode]] = []
        outgoing_edges: list = []

        # gotta pick one!
        # for now, we handle the most common case: both successors exist in the graph of the parent region, and
        # one successor has a path to the other successor
        if is_while and is_dowhile and self._parent_region is not None:
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
            loop_type = "while"
            continue_edges, outgoing_edges, continue_node, successor = result_while
        elif is_dowhile:
            loop_type = "do-while"
            continue_edges, outgoing_edges, continue_node, successor = result_dowhile

        if loop_type is None:
            # natural loop. select *any* exit edge to determine the successor
            # well actually, to maintain determinism, we select the successor with the highest address
            successor_candidates = set()
            for node in networkx.descendants(graph, loop_head):
                for succ in fullgraph.successors(node):
                    if succ not in graph:
                        successor_candidates.add(succ)
                    if loop_head is succ:
                        continue_edges.append((node, succ))
            if successor_candidates:
                successor_candidates = sorted(successor_candidates, key=lambda x: x.addr)
                successor = successor_candidates[0]
                # virtualize all other edges
                for succ in successor_candidates:
                    for pred in fullgraph.predecessors(succ):
                        if pred in graph:
                            outgoing_edges.append((pred, succ))

        if outgoing_edges:
            # if there is a single successor, we convert all out-going edges into breaks;
            # if there are multiple successors, and if the current region does not have a parent region, then we
            # convert all out-going edges into gotos;
            # otherwise we give up.

            if self._parent_region is not None and len({dst for _, dst in outgoing_edges}) > 1:
                # give up because there is a parent region
                return False

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
                    _, src_parent, src_block = self._find_node_going_to_dst(src, dst)
                    if src_block is None:
                        l.warning(
                            "Cannot find the source block jumping to the destination block at %#x. "
                            "This is likely a bug elsewhere and needs to be addressed.",
                            dst.addr,
                        )
                        # remove the edge anyway
                        fullgraph.remove_edge(src, dst)
                    elif not isinstance(src_block, (Block, MultiNode)):
                        # it has probably been structured into BreakNode or ConditionalBreakNode
                        # just remove the edge
                        fullgraph.remove_edge(src, dst)
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
                        break_cond = self.cond_proc.recover_edge_condition(fullgraph, src_block, dst)
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
                            break_node = ConditionNode(
                                last_src_stmt.ins_addr,
                                None,
                                break_cond,
                                break_node_inner,
                            )
                        new_node = SequenceNode(src_block.addr, nodes=[src_block, break_node])
                        if has_continue:
                            if self.is_a_jump_target(last_src_stmt, continue_node.addr):
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

                        self._remove_last_statement_if_jump(src_block)
                        fullgraph.remove_edge(src, dst)
                        if src_parent is not None:
                            # replace the node in its parent node
                            self.replace_node_in_node(src_parent, src_block, new_node)
                        else:
                            # directly replace the node in graph
                            self.replace_nodes(graph, src, new_node)
                            self.replace_nodes(fullgraph, src, new_node)
                            if src is loop_head:
                                loop_head = new_node
                            if src is continue_node:
                                continue_node = new_node

                        self._replace_node_in_edge_list(outgoing_edges, src_block, new_node)
                        self._replace_node_in_edge_list(continue_edges, src_block, new_node)

                        # remove the last jump or conditional jump in src_block
                        self._remove_last_statement_if_jump(src_block)

                else:
                    self.virtualized_edges.add((src, dst))
                    fullgraph.remove_edge(src, dst)
                    if fullgraph.in_degree[dst] == 0:
                        # drop this node
                        fullgraph.remove_node(dst)
                        if dst in self._region.successors:
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
                    continue

                # due to prior structuring of sub regions, the continue node may already be a Jump statement deep in
                # src at this point. we need to find the Jump statement and replace it.
                _, _, cont_block = self._find_node_going_to_dst(src, continue_node)
                if cont_block is None:
                    # cont_block is not found. but it's ok. one possibility is that src is a jump table head with one
                    # case being the loop head. in such cases, we can just remove the edge.
                    if src.addr not in self.kb.cfgs["CFGFast"].jump_tables:
                        l.debug(
                            "_refine_cyclic_core: Cannot find the block going to loop head for edge %r -> %r. "
                            "Remove the edge anyway.",
                            src,
                            continue_node,
                        )
                    if graph.has_edge(src, continue_node):
                        graph.remove_edge(src, continue_node)
                    fullgraph.remove_edge(src, continue_node)
                else:
                    # remove the edge.
                    graph.remove_edge(src, continue_node)
                    fullgraph.remove_edge(src, continue_node)
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

                        if new_cont_node is not None:
                            self._remove_last_statement_if_jump(cont_block)
                            new_node = SequenceNode(src.addr, nodes=[src, new_cont_node])
                            self.replace_nodes(graph, src, new_node)
                            self.replace_nodes(fullgraph, src, new_node)

        if loop_type == "do-while":
            self.dowhile_known_tail_nodes.add(continue_node)

        return bool(outgoing_edges or len(continue_edges) > 1)

    def _refine_cyclic_is_while_loop(
        self, graph, fullgraph, loop_head, head_succs
    ) -> tuple[bool, tuple[list, list, BaseNode, BaseNode] | None]:
        if len(head_succs) == 2 and any(head_succ not in graph for head_succ in head_succs):
            # make sure the head_pred is not already structured
            _, _, head_block_0 = self._find_node_going_to_dst(loop_head, head_succs[0])
            _, _, head_block_1 = self._find_node_going_to_dst(loop_head, head_succs[1])
            if head_block_0 is head_block_1 and head_block_0 is not None:
                # there is an out-going edge from the loop head
                # virtualize all other edges
                continue_edges: list[tuple[BaseNode, BaseNode]] = []
                outgoing_edges = []
                successor = next(iter(head_succ for head_succ in head_succs if head_succ not in graph))
                for node in networkx.descendants(graph, loop_head):
                    succs = list(fullgraph.successors(node))
                    if loop_head in succs:
                        continue_edges.append((node, loop_head))

                    outside_succs = [succ for succ in succs if succ not in graph]
                    for outside_succ in outside_succs:
                        outgoing_edges.append((node, outside_succ))

                return True, (continue_edges, outgoing_edges, loop_head, successor)
        return False, None

    def _refine_cyclic_is_dowhile_loop(  # pylint:disable=unused-argument
        self, graph, fullgraph, loop_head, head_succs
    ) -> tuple[bool, tuple[list, list, BaseNode, BaseNode] | None]:
        # check if there is an out-going edge from the loop tail
        head_preds = list(fullgraph.predecessors(loop_head))
        if len(head_preds) == 1:
            head_pred = head_preds[0]
            head_pred_succs = list(fullgraph.successors(head_pred))
            if len(head_pred_succs) == 2 and any(nn not in graph for nn in head_pred_succs):
                # make sure the head_pred is not already structured
                _, _, src_block_0 = self._find_node_going_to_dst(head_pred, head_pred_succs[0])
                _, _, src_block_1 = self._find_node_going_to_dst(head_pred, head_pred_succs[1])
                if src_block_0 is src_block_1 and src_block_0 is not None:
                    continue_edges: list[tuple[BaseNode, BaseNode]] = []
                    outgoing_edges = []
                    # there is an out-going edge from the loop tail
                    # virtualize all other edges
                    successor = next(iter(nn for nn in head_pred_succs if nn not in graph))
                    continue_node = head_pred
                    for node in networkx.descendants(graph, loop_head):
                        if node is head_pred:
                            continue
                        succs = list(fullgraph.successors(node))
                        if head_pred in succs:
                            continue_edges.append((node, head_pred))

                        outside_succs = [succ for succ in succs if succ not in graph]
                        for outside_succ in outside_succs:
                            outgoing_edges.append((node, outside_succ))

                    return True, (continue_edges, outgoing_edges, continue_node, successor)
        return False, None

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
            acyclic_graph.remove_edges_from(graph.in_edges(head))

            self._assert_graph_ok(acyclic_graph, "Removed wrong edges")

        for node in list(reversed(GraphUtils.quasi_topological_sort_nodes(acyclic_graph))):
            if node not in graph:
                continue
            if graph.has_edge(node, head):
                # it's a back edge. skip
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
        if isinstance(node, (SwitchCaseNode, IncompleteSwitchCaseNode)):
            return False

        r = self._match_acyclic_switch_cases_incomplete_switch_head(node, graph, full_graph)
        if r:
            return r
        jump_tables = self.kb.cfgs["CFGFast"].jump_tables
        r = self._match_acyclic_switch_cases_address_loaded_from_memory(node, graph, full_graph, jump_tables)
        if r:
            return r
        r = self._match_acyclic_switch_cases_address_computed(node, graph, full_graph, jump_tables)
        if r:
            return r
        return self._match_acyclic_incomplete_switch_cases(node, graph, full_graph, jump_tables)

    def _match_acyclic_switch_cases_incomplete_switch_head(self, node, graph, full_graph) -> bool:
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
        case_entries: dict[int, tuple[int, int | None]] = {}
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
            graph,
            full_graph,
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
            graph.add_edge(node, node_default)
            full_graph.add_edge(node, node_default)
        r = self._make_switch_cases_core(
            node,
            self.cond_proc.claripy_ast_from_ail_condition(last_stmt.switch_variable),
            cases,
            node_default_addr,
            node_default,
            last_stmt.ins_addr,
            to_remove,
            graph,
            full_graph,
            can_bail=True,
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

        self._switch_handle_gotos(cases, node_default, None)
        return True

    def _match_acyclic_switch_cases_address_loaded_from_memory(self, node, graph, full_graph, jump_tables) -> bool:
        try:
            last_stmt = self.cond_proc.get_last_statement(node)
        except EmptyBlockNotice:
            return False

        successor_addrs = extract_jump_targets(last_stmt)
        if len(successor_addrs) != 2:
            return False

        for t in successor_addrs:
            if t in jump_tables:
                # this is a candidate!
                target = t
                break
        else:
            return False

        jump_table = jump_tables[target]
        if jump_table.type != IndirectJumpType.Jumptable_AddressLoadedFromMemory:
            return False

        # extract the comparison expression, lower-, and upper-bounds from the last statement
        cmp = switch_extract_cmp_bounds(last_stmt)
        if not cmp:
            return False
        cmp_expr, cmp_lb, cmp_ub = cmp  # pylint:disable=unused-variable

        node_a = next(iter(nn for nn in graph.nodes if nn.addr == target), None)
        if node_a is None:
            return False

        # the default case
        node_b_addr = next(iter(t for t in successor_addrs if t != target), None)
        if node_b_addr is None:
            return False

        # populate whitelist_edges
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
        case_node_successors = set()
        for case_node in case_nodes:
            if case_node is node_pred:
                continue
            if case_node.addr in jump_table.jumptable_entries:
                succs = set(graph.successors(case_node))
                case_node_successors |= {succ for succ in succs if succ.addr not in jump_table.jumptable_entries}
        if len(case_node_successors) > 1:
            return False

        # we will definitely be able to structure this into a full switch-case. remove node from switch_case_known_heads
        self.switch_case_known_heads.remove(node)

        # un-structure IncompleteSwitchCaseNode
        if isinstance(node_a, SequenceNode) and node_a.nodes and isinstance(node_a.nodes[0], IncompleteSwitchCaseNode):
            _, new_seq_node = self._unpack_sequencenode_head(graph, node_a)
            self._unpack_sequencenode_head(full_graph, node_a, new_seq=new_seq_node)
            # update node_a
            node_a = next(iter(nn for nn in graph.nodes if nn.addr == target))
        if isinstance(node_a, IncompleteSwitchCaseNode):
            self._unpack_incompleteswitchcasenode(graph, node_a)
            self._unpack_incompleteswitchcasenode(full_graph, node_a)
            # update node_a
            node_a = next(iter(nn for nn in graph.nodes if nn.addr == target))

        cases, node_default, to_remove = self._switch_build_cases(
            {cmp_lb + i: entry_addr for (i, entry_addr) in enumerate(jump_table.jumptable_entries)},
            node,
            node_a,
            node_b_addr,
            graph,
            full_graph,
        )

        if node_default is None:
            switch_end_addr = node_b_addr
        else:
            # we don't know what the end address of this switch-case structure is. let's figure it out
            switch_end_addr = None
            to_remove.add(node_default)

        to_remove.add(node_a)  # add node_a
        self._make_switch_cases_core(
            node,
            cmp_expr,
            cases,
            node_b_addr,
            node_default,
            last_stmt.ins_addr,
            to_remove,
            graph,
            full_graph,
            node_a=node_a,
        )

        self._switch_handle_gotos(cases, node_default, switch_end_addr)

        return True

    def _match_acyclic_switch_cases_address_computed(self, node, graph, full_graph, jump_tables) -> bool:
        if node.addr not in jump_tables:
            return False
        jump_table = jump_tables[node.addr]
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
        else:
            return False

        cases, node_default, to_remove = self._switch_build_cases(
            {cmp_lb + i: entry_addr for (i, entry_addr) in enumerate(jump_table.jumptable_entries)},
            node,
            node,
            default_addr,
            graph,
            full_graph,
        )
        if node_default is None:
            # there must be a default case
            return False

        self._make_switch_cases_core(
            node, cmp_expr, cases, default_addr, node_default, node.addr, to_remove, graph, full_graph
        )

        return True

    def _match_acyclic_incomplete_switch_cases(
        self, node, graph: networkx.DiGraph, full_graph: networkx.DiGraph, jump_tables: dict
    ) -> bool:
        # sanity checks
        if node.addr not in jump_tables:
            return False
        if isinstance(node, IncompleteSwitchCaseNode):
            return False
        if is_empty_or_label_only_node(node):
            return False

        successors = list(graph.successors(node))

        if (
            successors
            and {succ.addr for succ in successors} == set(jump_tables[node.addr].jumptable_entries)
            and all(graph.in_degree[succ] == 1 for succ in successors)
        ):
            out_nodes = set()
            for succ in successors:
                out_nodes |= set(full_graph.successors(succ))
            out_nodes = list(out_nodes)
            if len(out_nodes) <= 1:
                new_node = IncompleteSwitchCaseNode(node.addr, node, successors)
                graph.remove_nodes_from(successors)
                self.replace_nodes(graph, node, new_node)
                if out_nodes and out_nodes[0] in graph:
                    graph.add_edge(new_node, out_nodes[0])
                full_graph.remove_nodes_from(successors)
                self.replace_nodes(full_graph, node, new_node)
                if out_nodes:
                    full_graph.add_edge(new_node, out_nodes[0])
                return True
        return False

    def _switch_build_cases(
        self,
        case_and_entryaddrs: dict[int, int | tuple[int, int | None]],
        head_node,
        node_a: BaseNode,
        node_b_addr,
        graph,
        full_graph,
    ) -> tuple[OrderedDict, Any, set[Any]]:
        cases: OrderedDict[int | tuple[int], SequenceNode] = OrderedDict()
        to_remove = set()

        # it is possible that the default node gets duplicated by other analyses and creates a default node (addr.a)
        # and a case node (addr.b). The addr.a node is a successor to the head node while the addr.b node is a
        # successor to node_a
        default_node_candidates = [nn for nn in graph.nodes if nn.addr == node_b_addr]
        if len(default_node_candidates) == 0:
            node_default: BaseNode | None = None
        elif len(default_node_candidates) == 1:
            node_default: BaseNode | None = default_node_candidates[0]
        else:
            node_default: BaseNode | None = next(
                iter(nn for nn in default_node_candidates if graph.has_edge(head_node, nn)), None
            )

        if node_default is not None and not isinstance(node_default, SequenceNode):
            # make the default node a SequenceNode so that we can insert Break and Continue nodes into it later
            new_node = SequenceNode(node_default.addr, nodes=[node_default])
            self.replace_nodes(graph, node_default, new_node)
            self.replace_nodes(full_graph, node_default, new_node)
            node_default = new_node

        # entry_addrs_set = set(jumptable_entries)
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
        node_default_addr: int,
        node_default,
        addr,
        to_remove: set,
        graph: networkx.DiGraph,
        full_graph: networkx.DiGraph,
        node_a=None,
        can_bail=False,
    ) -> bool:
        scnode = SwitchCaseNode(cmp_expr, cases, node_default, addr=addr)

        # insert the switch-case node to the graph
        other_nodes_inedges = []
        out_edges = []

        # remove all those entry nodes
        if node_default is not None:
            to_remove.add(node_default)

        for nn in to_remove:
            if nn is head:
                continue
            for src in graph.predecessors(nn):
                if src not in to_remove:
                    other_nodes_inedges.append((src, nn))
            for dst in full_graph.successors(nn):
                if dst not in to_remove:
                    out_edges.append((nn, dst))

        if can_bail:
            nonhead_out_nodes = {edge[1] for edge in out_edges if edge[1] is not head}
            if len(nonhead_out_nodes) > 1:
                # not ready to be structured yet - do it later
                return False

        if node_default is not None:
            # the head no longer goes to the default case
            graph.remove_edge(head, node_default)
            full_graph.remove_edge(head, node_default)
        else:
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

        if out_edges:
            # for all out edges going to head, we ensure there is a goto at the end of each corresponding case node
            for out_src, out_dst in out_edges:
                if out_dst is head:
                    all_case_nodes = list(cases.values())
                    if node_default is not None:
                        all_case_nodes.append(node_default)
                    case_node: SequenceNode = next(nn for nn in all_case_nodes if nn.addr == out_src.addr)
                    case_node_last_stmt = self.cond_proc.get_last_statement(case_node)
                    if not isinstance(case_node_last_stmt, Jump):
                        jump_stmt = Jump(
                            None, Const(None, None, head.addr, self.project.arch.bits), None, ins_addr=out_src.addr
                        )
                        jump_node = Block(out_src.addr, 0, statements=[jump_stmt])
                        case_node.nodes.append(jump_node)

            out_edges = [edge for edge in out_edges if edge[1] is not head]
            if out_edges:
                # leave only one out edge and virtualize all other out edges
                out_edge = out_edges[0]
                out_dst = out_edge[1]
                if out_dst in graph:
                    graph.add_edge(scnode, out_dst)
                full_graph.add_edge(scnode, out_dst)
                if full_graph.has_edge(head, out_dst):
                    full_graph.remove_edge(head, out_dst)

        # remove the last statement (conditional jump) in the head node
        remove_last_statement(head)

        if node_a is not None:
            # remove the last statement in node_a
            remove_last_statement(node_a)

        return True

    # other acyclic schemas

    def _match_acyclic_sequence(self, graph, full_graph, start_node) -> bool:
        """
        Check if there is a sequence of regions, where each region has a single predecessor and a single successor.
        """
        succs = list(graph.successors(start_node))
        if len(succs) == 1:
            end_node = succs[0]
            jump_tables = self.kb.cfgs["CFGFast"].jump_tables
            if (
                full_graph.out_degree[start_node] == 1
                and full_graph.in_degree[end_node] == 1
                and not full_graph.has_edge(end_node, start_node)
                and end_node.addr not in jump_tables
                and end_node not in self.switch_case_known_heads
                and start_node not in self.switch_case_known_heads
                and end_node not in self.dowhile_known_tail_nodes
            ):
                # merge two blocks
                new_seq = self._merge_nodes(start_node, end_node)

                # on the original graph
                self.replace_nodes(graph, start_node, new_seq, old_node_1=end_node if end_node in graph else None)
                # on the graph with successors
                self.replace_nodes(full_graph, start_node, new_seq, old_node_1=end_node)
                return True
        return False

    def _match_acyclic_ite(self, graph, full_graph, start_node) -> bool:
        """
        Check if start_node is the beginning of an If-Then-Else region. Create a Condition node if it is the case.
        """

        succs = list(full_graph.successors(start_node))
        if len(succs) == 2:
            left, right = succs
            if left in self.switch_case_known_heads or right in self.switch_case_known_heads:
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
                jump_tables = self.kb.cfgs["CFGFast"].jump_tables

                if (
                    full_graph.in_degree[left] == 1
                    and full_graph.in_degree[right] == 1
                    and left.addr not in jump_tables
                    and right.addr not in jump_tables
                ):
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                    edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                    if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                        # c = !c
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
                                graph.remove_node(left)
                            self.replace_nodes(graph, start_node, new_node, old_node_1=right)
                            # on the graph with successors
                            full_graph.remove_node(left)
                            self.replace_nodes(full_graph, start_node, new_node, old_node_1=right)
                        else:
                            # on the original graph
                            if right in graph:
                                graph.remove_node(right)
                            self.replace_nodes(graph, start_node, new_node, old_node_1=left)
                            # on the graph with successors
                            full_graph.remove_node(right)
                            self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)

                        return True

            if right in graph and not right_succs and full_graph.in_degree[right] == 1 and left in graph:
                # swap them
                left, right = right, left
                left_succs, right_succs = right_succs, left_succs
            if left in graph and not left_succs and full_graph.in_degree[left] == 1 and right in graph:
                # potentially If-Then
                jump_tables = self.kb.cfgs["CFGFast"].jump_tables

                if left.addr not in jump_tables and right.addr not in jump_tables:
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                    edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                    if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                        # c = !c
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
                        self.replace_nodes(graph, start_node, new_node, old_node_1=left)
                        # on the graph with successors
                        self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)

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
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c = !c
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
                    self.replace_nodes(graph, start_node, new_node, old_node_1=left)
                    # on the graph with successors
                    self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)

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
                    full_graph.in_degree[right] == 2
                    and left_succs == [right]
                    or full_graph.in_degree[right] == 1
                    and not left_succs
                )
            ):
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c = !c
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
                            new_cond_node.addr,
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
                    self.replace_nodes(graph, start_node, new_node, old_node_1=left)
                    # on the graph with successors
                    self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)

                    return True

        return False

    def _match_acyclic_short_circuit_conditions(
        self, graph: networkx.DiGraph, full_graph: networkx.DiGraph, start_node
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

        r = self._match_acyclic_short_circuit_conditions_type_a(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, right, left_right_cond, succ = r
            # create the condition node
            memo = {}
            if not self._is_single_statement_block(left):
                if not self._should_use_multistmtexprs(left):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(left)
                assert stmts is not None
                mstmt_expr = MultiStatementExpression(
                    None, stmts, self.cond_proc.convert_claripy_bool_ast(left_right_cond), ins_addr=left.addr
                )
                memo[left_right_cond._hash] = mstmt_expr
            cond = self.cond_proc.convert_claripy_bool_ast(
                claripy.Or(claripy.Not(left_cond), left_right_cond), memo=memo
            )
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

            self.replace_nodes(graph, start_node, new_node, old_node_1=left if left in graph else None)
            self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)

            return True

        r = self._match_acyclic_short_circuit_conditions_type_b(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, right, right_left_cond, else_node = r
            # create the condition node
            memo = {}
            if not self._is_single_statement_block(right):
                if not self._should_use_multistmtexprs(right):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(right)
                assert stmts is not None
                mstmt_expr = MultiStatementExpression(
                    None, stmts, self.cond_proc.convert_claripy_bool_ast(right_left_cond), ins_addr=left.addr
                )
                memo[right_left_cond._hash] = mstmt_expr
            cond = self.cond_proc.convert_claripy_bool_ast(claripy.Or(left_cond, right_left_cond), memo=memo)
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

            self.replace_nodes(graph, start_node, new_node, old_node_1=right if right in graph else None)
            self.replace_nodes(full_graph, start_node, new_node, old_node_1=right)

            return True

        r = self._match_acyclic_short_circuit_conditions_type_c(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, succ, left_succ_cond, right = r
            # create the condition node
            memo = {}
            if not self._is_single_statement_block(left):
                if not self._should_use_multistmtexprs(left):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(left)
                assert stmts is not None
                mstmt_expr = MultiStatementExpression(
                    None, stmts, self.cond_proc.convert_claripy_bool_ast(left_succ_cond), ins_addr=left.addr
                )
                memo[left_succ_cond._hash] = mstmt_expr
            cond = self.cond_proc.convert_claripy_bool_ast(
                claripy.And(left_cond, claripy.Not(left_succ_cond)), memo=memo
            )
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

            self.replace_nodes(graph, start_node, new_node, old_node_1=left if left in graph else None)
            self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)
            return True

        r = self._match_acyclic_short_circuit_conditions_type_d(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, right, right_left_cond, else_node = r
            # create the condition node
            memo = {}
            if not self._is_single_statement_block(left):
                if not self._should_use_multistmtexprs(left):
                    return False
                # create a MultiStatementExpression for left_right_cond
                stmts = self._build_multistatementexpr_statements(left)
                assert stmts is not None
                mstmt_expr = MultiStatementExpression(
                    None, stmts, self.cond_proc.convert_claripy_bool_ast(right_left_cond), ins_addr=left.addr
                )
                memo[right_left_cond._hash] = mstmt_expr
            cond = self.cond_proc.convert_claripy_bool_ast(
                claripy.And(left_cond, right_left_cond),
                memo=memo,
            )
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

            self.replace_nodes(graph, start_node, new_node, old_node_1=left if left in graph else None)
            self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)
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
            if (
                self._is_sequential_statement_block(left)
                and full_graph.in_degree[left] == 1
                and full_graph.in_degree[right] >= 1
            ):
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c0 = !c0
                    left_succs = list(full_graph.successors(left))
                    if len(left_succs) == 2 and right in left_succs:
                        other_succ = next(iter(succ for succ in left_succs if succ is not right))
                        if full_graph.out_degree[right] == 1 and full_graph.has_edge(right, other_succ):
                            # there must be an edge between right and other_succ
                            edge_cond_left_right = self.cond_proc.recover_edge_condition(full_graph, left, right)
                            edge_cond_left_other = self.cond_proc.recover_edge_condition(full_graph, left, other_succ)
                            if claripy.is_true(claripy.Not(edge_cond_left_right) == edge_cond_left_other):
                                # c1 = !c1
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

            if full_graph.in_degree[left] == 1 and full_graph.in_degree[right] == 2:
                left, right = right, left
            if (
                self._is_sequential_statement_block(right)
                and full_graph.in_degree[left] == 2
                and full_graph.in_degree[right] == 1
            ):
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c0 = !c0
                    right_succs = list(full_graph.successors(right))
                    left_succs = list(full_graph.successors(left))
                    if len(right_succs) == 2 and left in right_succs:
                        else_node = next(iter(succ for succ in right_succs if succ is not left))
                        if len([succ for succ in left_succs if succ is not else_node]) == 1:
                            edge_cond_right_left = self.cond_proc.recover_edge_condition(full_graph, right, left)
                            edge_cond_right_else = self.cond_proc.recover_edge_condition(full_graph, right, else_node)
                            if claripy.is_true(claripy.Not(edge_cond_right_left) == edge_cond_right_else):
                                # c1 = !c1
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
            if (
                self._is_sequential_statement_block(left)
                and full_graph.in_degree[left] == 1
                and full_graph.in_degree[successor] >= 1
            ):
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_successor = self.cond_proc.recover_edge_condition(full_graph, start_node, successor)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_successor):
                    # c0 = !c0
                    left_succs = list(full_graph.successors(left))
                    if len(left_succs) == 2 and successor in left_succs:
                        right = next(iter(succ for succ in left_succs if succ is not successor))
                        if full_graph.out_degree[right] == 1 and full_graph.has_edge(right, successor):
                            # there must be an edge from right to successor
                            edge_cond_left_right = self.cond_proc.recover_edge_condition(full_graph, left, right)
                            edge_cond_left_successor = self.cond_proc.recover_edge_condition(
                                full_graph, left, successor
                            )
                            if claripy.is_true(claripy.Not(edge_cond_left_right) == edge_cond_left_successor):
                                # c1 = !c1
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
            if (
                self._is_sequential_statement_block(left)
                and full_graph.in_degree[left] == 1
                and full_graph.in_degree[else_node] >= 1
            ):
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_else = self.cond_proc.recover_edge_condition(full_graph, start_node, else_node)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_else):
                    # c0 = !c0
                    left_succs = list(full_graph.successors(left))
                    if len(left_succs) == 2 and else_node in left_succs:
                        right = next(iter(succ for succ in left_succs if succ is not else_node))
                        edge_cond_left_right = self.cond_proc.recover_edge_condition(full_graph, left, right)
                        edge_cond_left_else = self.cond_proc.recover_edge_condition(full_graph, left, else_node)
                        if claripy.is_true(claripy.Not(edge_cond_left_right) == edge_cond_left_else):
                            # c1 = !c1
                            return left, edge_cond_left, right, edge_cond_left_right, else_node
        return None

    def _last_resort_refinement(self, head, graph: networkx.DiGraph, full_graph: networkx.DiGraph | None) -> bool:
        if self._improve_algorithm:
            while self._edge_virtualization_hints:
                src, dst = self._edge_virtualization_hints.pop(0)
                if graph.has_edge(src, dst):
                    self._virtualize_edge(graph, full_graph, src, dst)
                    l.debug("last_resort: Removed edge %r -> %r (type 3)", src, dst)
                    return True

        # virtualize an edge to allow progressing in structuring
        all_edges_wo_dominance = []  # to ensure determinism, edges in this list are ordered by a tuple of
        # (src_addr, dst_addr)
        secondary_edges = []  # likewise, edges in this list are ordered by a tuple of (src_addr, dst_addr)
        other_edges = []
        idoms = networkx.immediate_dominators(full_graph, head)
        if networkx.is_directed_acyclic_graph(full_graph):
            acyclic_graph = full_graph
        else:
            acyclic_graph = to_acyclic_graph(full_graph, loop_heads=[head])
        for src, dst in acyclic_graph.edges:
            if src is dst:
                continue
            if src not in graph:
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

        ordered_nodes = GraphUtils.quasi_topological_sort_nodes(acyclic_graph, loop_heads=[head])
        node_seq = {nn: (len(ordered_nodes) - idx) for (idx, nn) in enumerate(ordered_nodes)}  # post-order

        if all_edges_wo_dominance:
            all_edges_wo_dominance = self._order_virtualizable_edges(full_graph, all_edges_wo_dominance, node_seq)
            # virtualize the first edge
            src, dst = all_edges_wo_dominance[0]
            self._virtualize_edge(graph, full_graph, src, dst)
            l.debug("last_resort: Removed edge %r -> %r (type 1)", src, dst)
            return True

        if secondary_edges:
            secondary_edges = self._order_virtualizable_edges(full_graph, secondary_edges, node_seq)
            # virtualize the first edge
            src, dst = secondary_edges[0]
            self._virtualize_edge(graph, full_graph, src, dst)
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
        if full_graph is not None:
            self.virtualized_edges.add((src, dst))
            full_graph.remove_edge(src, dst)
            if new_src is not None:
                self.replace_nodes(full_graph, src, new_src)
        if remove_src_last_stmt:
            remove_last_statement(src)

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
            return True
        if self._use_multistmtexprs == MultiStmtExprMode.MAX_ONE_CALL:
            # count the number of calls
            ctr = AILCallCounter()
            ctr.walk(node)
            return ctr.calls <= 1
        l.warning("Unsupported enum value for _use_multistmtexprs: %s", self._use_multistmtexprs)
        return False

    @staticmethod
    def _find_node_going_to_dst(
        node: SequenceNode,
        dst: Block | BaseNode,
        last=True,
        condjump_only=False,
    ) -> tuple[int | None, BaseNode | None, Block | None]:
        """

        :param node:
        :param dst_addr:
        :param dst_idx:
        :return:            A tuple of (parent node, node who has a successor of dst_addr)
        """

        dst_addr = dst.addr
        dst_idx = dst.idx if isinstance(dst, Block) else ...

        def _check(last_stmt):
            return (
                (
                    not condjump_only
                    and isinstance(last_stmt, Jump)
                    and isinstance(last_stmt.target, Const)
                    and last_stmt.target.value == dst_addr
                    and (dst_idx is ... or last_stmt.target_idx == dst_idx)
                )
                or isinstance(last_stmt, ConditionalJump)
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
                    walker.block_id += 1

                if _check(first_stmt):
                    walker.parent_and_block.append((walker.block_id, parent, block))
                elif len(block.statements) > 1:
                    last_stmt = block.statements[-1]
                    if _check(last_stmt) or (
                        not isinstance(last_stmt, (Jump, ConditionalJump))
                        and block.addr + block.original_size == dst_addr
                    ):
                        walker.parent_and_block.append((walker.block_id, parent, block))

        def _handle_MultiNode(block: MultiNode, parent=None, **kwargs):  # pylint:disable=unused-argument
            if block.nodes and isinstance(block.nodes[-1], Block) and block.nodes[-1].statements:
                first_stmt = first_nonlabel_nonphi_statement(block)
                if first_stmt is not None:
                    # this block has content. increment the block ID counter
                    walker.block_id += 1
                if _check(block.nodes[-1].statements[-1]):
                    walker.parent_and_block.append((walker.block_id, parent, block))

        def _handle_BreakNode(break_node: BreakNode, parent=None, **kwargs):  # pylint:disable=unused-argument
            walker.block_id += 1
            if (
                break_node.target == dst_addr
                or isinstance(break_node.target, Const)
                and break_node.target.value == dst_addr
            ):
                # FIXME: idx is ignored
                walker.parent_and_block.append((walker.block_id, parent, break_node))

        walker = SequenceWalker(
            handlers={
                Block: _handle_Block,
                MultiNode: _handle_MultiNode,
                BreakNode: _handle_BreakNode,
            },
            update_seqnode_in_place=False,
            force_forward_scan=True,
        )
        walker.parent_and_block: list[tuple[int, Any, Block | MultiNode]] = []
        walker.block_id = -1
        walker.walk(node)
        if not walker.parent_and_block:
            return None, None, None
        if last:
            return walker.parent_and_block[-1]
        return walker.parent_and_block[0]

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
    def _unpack_incompleteswitchcasenode(graph: networkx.DiGraph, incscnode: IncompleteSwitchCaseNode):
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

        def _to_statement_list(node: Block | MultiNode | SequenceNode) -> list[Statement]:
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
    def _remove_first_statement_if_jump(node: BaseNode | Block) -> Jump | ConditionalJump | None:
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
            return -node_seq.get(dst), dst_in_degree, src_out_degree, -src.addr, -dst.addr

        return sorted(edges, key=_sort_edge, reverse=True)

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

        for src, dst in graph.edges:
            graph_with_str.add_edge(f'"{src!r}"', f'"{dst!r}"')

        networkx.drawing.nx_pydot.write_dot(graph_with_str, path)
