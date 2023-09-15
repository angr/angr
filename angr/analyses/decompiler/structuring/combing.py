from typing import Dict, Optional, Any, Tuple, List, DefaultDict, OrderedDict as ODict, Set, Union, TYPE_CHECKING
from itertools import count
from collections import defaultdict, OrderedDict
import logging

import networkx

import ailment
from ailment import Block
from ailment.expression import Const, Register, BinaryOp
from ailment.statement import Jump, ConditionalJump, Assignment
import claripy

from angr.knowledge_plugins.cfg import IndirectJumpType
from angr.utils.constants import SWITCH_MISSING_DEFAULT_NODE_ADDR
from angr.utils.graph import dfs_back_edges, dominates, GraphUtils
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.utils import (
    extract_jump_targets,
    switch_extract_cmp_bounds,
    is_empty_or_label_only_node,
    remove_last_statement,
)
from .structurer_base import StructurerBase, EmptyBlockNotice
from .structurer_nodes import (
    BaseNode,
    MultiNode,
    SequenceNode,
    ConditionNode,
    LoopNode,
    SwitchCaseNode,
    IncompleteSwitchCaseNode,
    IncompleteSwitchCaseHeadStatement,
)

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


_l = logging.getLogger(__name__)
_DEBUG = False

if _DEBUG:
    from angr.utils.graph import dump_graph

    _l.setLevel(logging.DEBUG)


# an ever-incrementing counter
LOOP_HEAD_DISPATCHER_ADDR = count(0xFF010000)


class NodeDuplicator(SequenceWalker):
    """
    Duplicates an arbitrary structurer node.
    """

    def __init__(self, node_id_manager):
        super().__init__(
            handlers={
                ailment.Block: self._handle_Block,
            },
            update_seqnode_in_place=False,
        )
        self._node_id_manager = node_id_manager

    def _handle_Block(self, node: ailment.Block, **kwargs) -> ailment.Block:
        new_node = node.copy()
        new_node.idx = self._node_id_manager.next_node_id(new_node.addr)
        return new_node

    def _handle_Sequence(self, node: SequenceNode, **kwargs) -> SequenceNode:
        seq = super()._handle_Sequence(node, **kwargs)
        assert seq is not node
        if seq is None:
            # make a copy anyway
            seq = node.copy()
        seq.idx = self._node_id_manager.next_node_id(seq.addr)
        return seq

    def _handle_MultiNode(self, node: MultiNode, **kwargs) -> MultiNode:
        mn = super()._handle_MultiNode(node, **kwargs)
        assert mn is not node and mn is not None
        mn.idx = self._node_id_manager.next_node_id(mn.addr)
        return mn


class CombingStructurer(StructurerBase):
    """
    Structure a region using a structuring algorithm that is similar to the one described in the paper "A Comb for
    Decompiled C Code." Note that this implementation is not exactly the same as what the paper described (especially
    since some key details necessary for reproducing were missing in the original paper) and *should not* be used to
    evaluate the performance of the original algorithm described in the paper.
    """

    NAME = "combing"

    def __init__(
        self,
        region,
        parent_map=None,
        condition_processor=None,
        func: Optional["Function"] = None,
        case_entry_to_switch_head: Optional[Dict[int, int]] = None,
        parent_region=None,
        improve_structurer: bool = False,
        **kwargs,
    ):
        super().__init__(
            region,
            parent_map=parent_map,
            condition_processor=condition_processor,
            func=func,
            case_entry_to_switch_head=case_entry_to_switch_head,
            parent_region=parent_region,
            improve_structurer=improve_structurer,
            **kwargs,
        )
        self.switch_case_known_heads = set()

        self._analyze()

    def _analyze(self):
        has_cycle = self._preprocess()

        # at this point the graph is a directed acyclic graph.
        self._comb()

        # after combing, we can finally match without generating any goto statements!
        self.result = self._match_constructs(has_cycle)

        if self.result is None and self._region.head not in self._region.graph:
            # update the head
            self._region.head = next(
                iter(node for node in self._region.graph.nodes if node.addr == self._region.head.addr)
            )

    def _preprocess(self) -> bool:
        """
        Make the graph a directed acyclic graph and get it ready for combing.
        """

        # TODO: Handle jump-table-based switch-case constructs

        has_cycles = self._has_cycle()

        if has_cycles:
            region_head, abnormal_retreating_edges = self._elect_region_head()

            if abnormal_retreating_edges:
                region_head = self._normalize_retreating_edges(region_head, abnormal_retreating_edges)
                # no more abnormal retreating edges after this step

            self._region.head = region_head

            self._remove_retreating_edges()
            self._remove_break_edges()

        return has_cycles

    def _elect_region_head(self) -> Tuple[Any, List[Tuple[Any, Any]]]:
        """
        Find all retreating edges, and then return the node with the highest number of retreating edges as the
        destination node.

        This function is only called on cyclic graphs.

        :return:    The elected region head.
        """

        # find retreating edges
        retreating_edges = list(dfs_back_edges(self._region.graph, self._region.head))

        retreating_edge_count_by_dst = defaultdict(int)
        for _, dst in retreating_edges:
            retreating_edge_count_by_dst[dst] += 1
        highest_count = max(retreating_edge_count_by_dst.values())

        retreating_dsts = []
        for dst, count in retreating_edge_count_by_dst.items():
            if count == highest_count:
                retreating_dsts.append(dst)

        retreating_dsts = sorted(retreating_edge_count_by_dst, key=lambda x: x.addr, reverse=True)
        elected_loop_head = retreating_dsts[0]
        abnormal_retreating_edges = [(src, dst) for src, dst in retreating_edges if dst is not elected_loop_head]

        return elected_loop_head, abnormal_retreating_edges

    def _normalize_retreating_edges(self, region_head: Any, abnormal_retreating_edges: List[Tuple[Any, Any]]):
        """
        Create a new variable and assign a unique identifier for each node with an incoming retreating edge. The region
        head is always assigned 0 as its unique identifier.

        :param region_head:
        :param abnormal_retreating_edges:
        :return:
        """

        state_var_offset, _ = self._variable_creator.next_variable()
        state_variable = Register(state_var_offset, None, state_var_offset, self.project.arch.bits)

        # build the head dispatcher
        head_dispatcher = None
        last_head_dispatcher = None

        retreating_edge_dsts = [region_head] + sorted(
            (dst for _, dst in abnormal_retreating_edges), key=lambda x: x.addr
        )
        retreating_edge_srcs = dict(
            (dst, sorted(self._region.graph.predecessors(dst), key=lambda x: x.addr)) for dst in retreating_edge_dsts
        )

        for idx, dst in enumerate(retreating_edge_dsts):
            if idx == len(retreating_edge_dsts) - 1:
                assert last_head_dispatcher is not None
                last_head_dispatcher.statements[-1].false_target = Const(None, None, dst.addr, self.project.arch.bits)
                self._region.graph.add_edge(last_head_dispatcher, dst)
                if self._region.graph_with_successors is not None:
                    self._region.graph_with_successors.add_edge(last_head_dispatcher, dst)
            else:
                if idx == 0:
                    node_addr = region_head.addr
                else:
                    node_addr = next(LOOP_HEAD_DISPATCHER_ADDR)

                node = Block(
                    node_addr,
                    0,
                    statements=[
                        ConditionalJump(
                            None,
                            BinaryOp(
                                None,
                                "CmpEQ",
                                [state_variable, Const(None, None, dst.addr, self.project.arch.bits)],
                                False,
                                bits=1,
                                ins_addr=node_addr,
                            ),
                            Const(None, None, dst.addr, self.project.arch.bits),
                            None,  # we back-patch the false addr into it later
                            ins_addr=node_addr,
                        ),
                    ],
                )
                if head_dispatcher is None:
                    head_dispatcher = node
                if last_head_dispatcher is None:
                    self._region.graph.add_node(head_dispatcher)
                    if self._region.graph_with_successors is not None:
                        self._region.graph_with_successors.add_node(head_dispatcher)
                else:
                    last_head_dispatcher.statements[-1].false_target = Const(
                        None, None, node_addr, self.project.arch.bits
                    )
                    self._region.graph.add_edge(last_head_dispatcher, node)
                    if self._region.graph_with_successors is not None:
                        self._region.graph_with_successors.add_edge(last_head_dispatcher, node)

                self._region.graph.add_edge(node, dst)
                if self._region.graph_with_successors is not None:
                    self._region.graph_with_successors.add_edge(node, dst)

                last_head_dispatcher = node

        # update sources of each retreating edge - they must all jump to nodes that set up the state variable accordingly
        for dst in retreating_edge_dsts:
            for src in retreating_edge_srcs[dst]:
                last_stmts = self.cond_proc.get_last_statements(src)
                value_setting_node_addr = next(LOOP_HEAD_DISPATCHER_ADDR)
                updated = False
                for last_stmt in last_stmts:
                    if isinstance(last_stmt, Jump):
                        if isinstance(last_stmt.target, Const) and last_stmt.target.value == dst.addr:
                            # update the statement in-place
                            last_stmt.target = Const(
                                last_stmt.target.idx, None, value_setting_node_addr, self.project.arch.bits
                            )
                            updated = True
                    elif isinstance(last_stmt, ConditionalJump):
                        if isinstance(last_stmt.true_target, Const) and last_stmt.true_target.value == dst.addr:
                            # update the statement in-place
                            last_stmt.true_target = Const(
                                last_stmt.true_target.idx, None, value_setting_node_addr, self.project.arch.bits
                            )
                            updated = True
                        if isinstance(last_stmt.false_target, Const) and last_stmt.false_target.value == dst.addr:
                            # update the statement in-place
                            last_stmt.false_target = Const(
                                last_stmt.false_target.idx, None, value_setting_node_addr, self.project.arch.bits
                            )
                            updated = True

                if updated:
                    value_setting_node = Block(
                        value_setting_node_addr,
                        0,
                        statements=[
                            Assignment(
                                None,
                                state_variable,
                                Const(None, None, dst.addr, self.project.arch.bits),
                                ins_addr=value_setting_node_addr,
                            ),
                            Jump(
                                None,
                                Const(None, None, head_dispatcher.addr, self.project.arch.bits),
                                target_idx=dst.idx if hasattr(dst, "idx") else None,
                                ins_addr=value_setting_node_addr,
                            ),
                        ],
                    )
                    # remove the retreating edge
                    self._region.graph.remove_edge(src, dst)
                    # add edges accordingly
                    self._region.graph.add_edge(src, value_setting_node)
                    self._region.graph.add_edge(value_setting_node, head_dispatcher)
                    if self._region.graph_with_successors is not None:
                        # remove the retreating edge
                        self._region.graph_with_successors.remove_edge(src, dst)
                        # add new edges accordingly
                        self._region.graph_with_successors.add_edge(src, value_setting_node)
                        self._region.graph_with_successors.add_edge(value_setting_node, head_dispatcher)

        return head_dispatcher

    def _remove_retreating_edges(self):
        """
        Remove all edges pointing to the head.
        """

        normal_retreating_edges = [(src, dst) for src, dst in self._region.graph.edges if dst is self._region.head]

        for src, dst in normal_retreating_edges:
            self._region.graph.remove_edge(src, dst)
            if self._region.graph_with_successors is not None:
                self._region.graph_with_successors.remove_edge(src, dst)

    def _remove_break_edges(self):
        """
        Remove all edges going to the loop successor in the full graph.
        """

        if self._region.graph_with_successors is None:
            return
        if len(self._region.successors) != 1:
            return
        succ = next(iter(self._region.successors))
        break_edges = [(src, dst) for src, dst in self._region.graph_with_successors.edges if dst is succ]

        for src, dst in break_edges:
            self._region.graph_with_successors.remove_edge(src, dst)

    def _comb(self):
        """
        At this point, the region graph is finally a directed acyclic graph. We comb it as described in the paper.

        :return:
        """

        g = self._region.graph
        full_g = self._region.graph_with_successors
        # ensure the graph has only one exit node
        exit_nodes = [node for node in g if g.out_degree[node] == 0]

        if len(exit_nodes) > 1:
            dummy_exit_node = "Dummy"
            for en in exit_nodes:
                g.add_edge(en, dummy_exit_node)
            exit_node = dummy_exit_node
        else:
            assert len(exit_nodes) == 1
            dummy_exit_node = None
            exit_node = exit_nodes[0]

        _l.debug("Combing region %r", self._region)

        while True:
            # comb the entire graph
            while True:
                any_node_combed = self._comb_core(g, full_g, exit_node, dummy_exit_node)
                if not any_node_combed:
                    break

            dummy_node_inserted = self._ensure_two_predecessors(g, full_g, dummy_exit_node)
            if not dummy_node_inserted:
                break

        if dummy_exit_node is not None:
            g.remove_node(dummy_exit_node)

    def _comb_core(
        self, g: networkx.DiGraph, full_g: networkx.DiGraph, exit_node: Any, dummy_exit_node: Optional[str]
    ) -> bool:
        """
        Comb a conditional node.

        :param g:
        :param full_g:
        :param exit_node:
        :param dummy_exit_node:
        :return:    True if we have combed a node. False otherwise.
        """

        cfg = self.kb.cfgs["CFGFast"]

        # find all immediate post dominators
        idoms, ipostdoms = self.idoms_and_ipostdoms(g, self._region.head, exit_node)
        combed = False

        for node in list(reversed(GraphUtils.quasi_topological_sort_nodes(g))):
            if node is dummy_exit_node:
                continue

            if node.addr in cfg.jump_tables:
                continue

            if g.out_degree[node] == 2:
                # for each condition node, find all nodes between this node and its immediate post-dominator
                ipostdom = ipostdoms[node]

                slice = self._find_nodes_between(g, node, ipostdom)
                # note that slice does not include ipostdom. however, we may decide to duplicate ipostdom if there
                # will be more than two predecessors entering ipostdom, in order to enforce the Two Predecessors rule

                for nn in slice:
                    if not dominates(idoms, node, nn):
                        _l.debug("Duplicate node %r.", nn)
                        # duplicate this node!
                        self._apply_node_duplication(g, full_g, idoms, node, nn)

                        # update idoms and ipostdoms
                        idoms, ipostdoms = self.idoms_and_ipostdoms(g, self._region.head, exit_node)
                        combed = True

                # check the in-degree of ipostdom
                if ipostdom is not dummy_exit_node and g.in_degree[ipostdom] > 2:
                    # duplicate ipostdom
                    #
                    # honestly I think Figure 10 (c) and Figure 11 (b) in the original paper conflict with each other.
                    # how do we determine when to insert a dummy node and when to duplicate all the way until the end
                    # of the world? my best guess is that there are some missing details in the paper that we have no
                    # way to know besides reverse engineering rev.ng.
                    # for now, we resort to aggressively duplicating ipostdom if it has too many incoming edges.
                    self._apply_node_duplication(g, full_g, idoms, node, ipostdom)
                    idoms, ipostdoms = self.idoms_and_ipostdoms(g, self._region.head, exit_node)
                    combed = True

        return combed

    def _ensure_two_predecessors(
        self, graph: networkx.DiGraph, full_graph: networkx.DiGraph, dummy_node: Optional[str]
    ) -> bool:
        """
        Insert dummy nodes to ensure the two-predecessor property.
        """

        _l.debug("Enforcing the Two Predecessors rule.")

        nodes_with_more_than_two_preds = []
        for node in graph:
            if node is not dummy_node and graph.in_degree[node] > 2:
                nodes_with_more_than_two_preds.append(node)

        for node in nodes_with_more_than_two_preds:
            preds = sorted(list(graph.predecessors(node)), key=lambda x: x.addr)
            assert node not in preds  # there should be no loops

            prev_pred = preds[0]
            graph.remove_edge(prev_pred, node)
            full_graph.remove_edge(prev_pred, node)
            for i in range(1, len(preds) - 1):
                a = preds[i]
                dummy = SequenceNode(node.addr, nodes=[], idx=self._node_id_manager.next_node_id(node.addr))
                graph.remove_edge(a, node)
                full_graph.remove_edge(a, node)

                graph.add_edge(prev_pred, dummy)
                full_graph.add_edge(prev_pred, dummy)
                graph.add_edge(a, dummy)
                full_graph.add_edge(a, dummy)
                prev_pred = dummy
            graph.add_edge(prev_pred, node)
            full_graph.add_edge(prev_pred, node)

            assert graph.in_degree[node] == 2

        if nodes_with_more_than_two_preds:
            _l.debug("... enforced")
        return bool(nodes_with_more_than_two_preds)

    def _match_constructs(self, has_cycles: bool) -> Optional[BaseNode]:
        while True:
            any_matched = self._match_acyclic_schemas(
                self._region.graph,
                self._region.graph_with_successors
                if self._region.graph_with_successors is not None
                else networkx.DiGraph(self._region.graph),
            )
            if len(self._region.graph) == 1:
                break
            if not any_matched:
                # nothing can be matched while there is still more than one remaining node
                # we return the entire region
                return None

        node = next(iter(self._region.graph))

        if has_cycles:
            # wrap everything into a while-true loop
            if not isinstance(node, SequenceNode):
                node = SequenceNode(node.addr, nodes=[node])
            node = LoopNode("while", None, node, addr=node.addr)

            # add the edge going to the successor node
            # not necessary
            # if self._region.graph_with_successors and len(self._region.successors):
            #     succ = next(iter(self._region.successors))
            #     self._region.graph_with_successors.add_edge()

            # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
            self._rewrite_conditional_jumps_to_breaks(
                node.sequence_node, [succ.addr for succ in self._region.successors]
            )
            # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
            self._rewrite_jumps_to_continues(node.sequence_node)

        return node

    def _match_acyclic_schemas(self, graph: networkx.DiGraph, full_graph: networkx.DiGraph) -> bool:
        any_matches = False

        for node in list(reversed(GraphUtils.quasi_topological_sort_nodes(graph))):
            matched = self._match_acyclic_switch_cases(graph, full_graph, node)
            any_matches |= matched
            if matched:
                break
            matched = self._match_acyclic_sequence(graph, full_graph, node)
            any_matches |= matched
            if matched:
                break
            matched = self._match_acyclic_ite(graph, full_graph, node)
            any_matches |= matched
            if matched:
                break

        return any_matches

    def _match_acyclic_sequence(self, graph: networkx.DiGraph, full_graph: networkx.DiGraph, start_node: Any) -> bool:
        """
        Check if there is a sequence of regions, where each region has a single predecessor and a single successor.
        """
        succs = list(graph.successors(start_node))
        if len(succs) == 1:
            end_node = succs[0]
            if (
                full_graph.out_degree[start_node] == 1
                and full_graph.in_degree[end_node] == 1
                and not full_graph.has_edge(end_node, start_node)
            ):
                # merge two blocks
                new_seq = self._merge_nodes(start_node, end_node)

                # on the original graph
                self.replace_nodes(graph, start_node, new_seq, old_node_1=end_node if end_node in graph else None)
                # on the graph with successors
                self.replace_nodes(full_graph, start_node, new_seq, old_node_1=end_node)
                return True
        return False

    def _match_acyclic_ite(self, graph: networkx.DiGraph, full_graph: networkx.DiGraph, start_node: Any) -> bool:
        """
        Check if start_node is the beginning of an If-Then-Else region. Create a Condition node if it is the case.
        """

        succs = list(full_graph.successors(start_node))
        if len(succs) == 2:
            left, right = succs

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
                # FIXME: Record which jump tables have been structured in recursive structurer, instead of testing if
                # FIXME: left/right is a Block or a MultiNode

                if (
                    full_graph.in_degree[left] == 1
                    and full_graph.in_degree[right] == 1
                    and (left.addr not in jump_tables or not isinstance(left, (Block, MultiNode)))
                    and (right.addr not in jump_tables or not isinstance(right, (Block, MultiNode)))
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

                if (left.addr not in jump_tables or not isinstance(left, (Block, MultiNode))) and (
                    right.addr not in jump_tables or not isinstance(right, (Block, MultiNode))
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

            if len(right_succs) == 1 and right_succs[0] == left:
                # swap them
                left, right = right, left
                left_succs, right_succs = right_succs, left_succs
            if left in graph and len(left_succs) == 1 and left_succs[0] == right:
                # potentially If-Then
                if full_graph.in_degree[left] == 1 and full_graph.in_degree[right] >= 2:
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
            if left in graph and right not in graph:
                # potentially If-then
                if full_graph.in_degree[left] == 1 and (
                    full_graph.in_degree[right] >= 2
                    and left_succs == [right]
                    or full_graph.in_degree[right] >= 1
                    and not left_succs
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
                            new_jump_node = ailment.Block(
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
        r = self._match_acyclic_incomplete_switch_cases(node, graph, full_graph, jump_tables)
        return r

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
        case_entries: Dict[int, int] = {}
        for _, case_value, case_target_addr, _ in last_stmt.case_addrs:
            if isinstance(case_value, str):
                if case_value == "default":
                    node_default_addr = case_target_addr
                    continue
                raise ValueError(f"Unsupported 'case_value' {case_value}")
            case_entries[case_value] = case_target_addr

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
            node_default,
            last_stmt.ins_addr,
            to_remove,
            graph,
            full_graph,
            can_bail=True,
        )
        if not r:
            # restore the graph to cascading if-then-elses
            _l.warning("Cannot structure as a switch-case. Restore the sub graph to if-elses.")

            # delay this import, since it's cyclic for anyone who uses Structuring in their optimizations
            from ..optimization_passes.lowered_switch_simplifier import LoweredSwitchSimplifier

            LoweredSwitchSimplifier.restore_graph(node, last_stmt, graph, full_graph)
            raise GraphChangedNotification()

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

        node_a = next(iter(nn for nn in graph.nodes if nn.addr == target))
        # the default case
        node_b_addr = next(iter(t for t in successor_addrs if t != target))

        self.switch_case_known_heads.add(node)

        # sanity check: case nodes are successors to node_a. all case nodes must have at most common one successor
        node_pred = None
        if graph.in_degree[node] == 1:
            node_pred = list(graph.predecessors(node))[0]

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
            node, cmp_expr, cases, node_default, last_stmt.ins_addr, to_remove, graph, full_graph, node_a=node_a
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

        self._make_switch_cases_core(node, cmp_expr, cases, node_default, node.addr, to_remove, graph, full_graph)

        return True

    def _match_acyclic_incomplete_switch_cases(
        self, node, graph: networkx.DiGraph, full_graph: networkx.DiGraph, jump_tables: Dict
    ) -> bool:
        # sanity checks
        if node.addr not in jump_tables:
            return False
        if isinstance(node, IncompleteSwitchCaseNode):
            return False
        if is_empty_or_label_only_node(node):
            return False

        successors = list(graph.successors(node))

        if successors and all(graph.in_degree[succ] == 1 for succ in successors):
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
        self, case_and_entryaddrs: Dict[int, int], head_node, node_a: BaseNode, node_b_addr, graph, full_graph
    ) -> Tuple[ODict, Any, Set[Any]]:
        cases: ODict[Union[int, Tuple[int]], SequenceNode] = OrderedDict()
        to_remove = set()

        # it is possible that the default node gets duplicated by other analyses and creates a default node (addr.a)
        # and a case node (addr.b). The addr.a node is a successor to the head node while the addr.b node is a
        # successor to node_a
        default_node_candidates = [nn for nn in graph.nodes if nn.addr == node_b_addr]
        if len(default_node_candidates) == 0:
            node_default: Optional[BaseNode] = None
        elif len(default_node_candidates) == 1:
            node_default: Optional[BaseNode] = default_node_candidates[0]
        else:
            node_default: Optional[BaseNode] = next(
                iter(nn for nn in default_node_candidates if graph.has_edge(head_node, nn)), None
            )

        if node_default is not None and not isinstance(node_default, SequenceNode):
            # make the default node a SequenceNode so that we can insert Break and Continue nodes into it later
            new_node = SequenceNode(node_default.addr, nodes=[node_default])
            self.replace_nodes(graph, node_default, new_node)
            self.replace_nodes(full_graph, node_default, new_node)
            node_default = new_node

        # entry_addrs_set = set(jumptable_entries)
        converted_nodes: Dict[int, Any] = {}
        entry_addr_to_ids: DefaultDict[int, Set[int]] = defaultdict(set)

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
            if not node_b_in_node_a_successors and entry_addr == node_b_addr:
                # jump to default or end of the switch-case structure - ignore this case
                continue

            entry_addr_to_ids[entry_addr].add(case_idx)
            if entry_addr in converted_nodes:
                continue

            if entry_addr == self._region.head.addr:
                # do not make the region head part of the switch-case construct (because it will lead to the removal
                # of the region head node). replace this entry with a goto statement later.
                entry_node = None
            else:
                entry_node = next(iter(nn for nn in node_a_successors if nn.addr == entry_addr), None)
            if entry_node is None:
                # Missing entries. They are probably *after* the entire switch-case construct. Replace it with an empty
                # Goto node.
                case_inner_node = Block(
                    0,
                    0,
                    statements=[
                        Jump(None, Const(None, None, entry_addr, self.project.arch.bits), ins_addr=0, stmt_idx=0)
                    ],
                )
                case_node = SequenceNode(0, nodes=[case_inner_node])
                converted_nodes[entry_addr] = case_node
                continue

            if isinstance(entry_node, SequenceNode):
                case_node = entry_node
            else:
                case_node = SequenceNode(entry_node.addr, nodes=[entry_node])
            to_remove.add(entry_node)

            converted_nodes[entry_addr] = case_node

        for entry_addr, converted_node in converted_nodes.items():
            case_ids = entry_addr_to_ids[entry_addr]
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
        cases: ODict,
        node_default,
        addr,
        to_remove: Set,
        graph: networkx.DiGraph,
        full_graph: networkx.DiGraph,
        node_a=None,
        can_bail=False,
    ) -> bool:
        if node_default is not None:
            # the head no longer goes to the default case
            graph.remove_edge(head, node_default)
            full_graph.remove_edge(head, node_default)

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
                    case_node: SequenceNode = [nn for nn in all_case_nodes if nn.addr == out_src.addr][0]
                    case_node_last_stmt = self.cond_proc.get_last_statement(case_node)
                    if not isinstance(case_node_last_stmt, Jump):
                        jump_stmt = Jump(
                            None, Const(None, None, head.addr, self.project.arch.bits), None, ins_addr=out_src.addr
                        )
                        jump_node = Block(out_src.addr, 0, statements=[jump_stmt])
                        case_node.nodes.append(jump_node)
                    graph.add_edge(scnode, head)
                    full_graph.add_edge(scnode, head)

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

    def _apply_node_duplication(
        self, g: networkx.DiGraph, full_g: Optional[networkx.DiGraph], idoms: Dict, head: Any, nn: Any
    ):
        duplicator = NodeDuplicator(self._node_id_manager)
        dup_node = duplicator.walk(nn)

        # split the edges into two sets
        preds = list(g.predecessors(nn))
        preds_dom_by_node = [pred for pred in preds if dominates(idoms, head, pred)]
        preds_not_dom_by_node = [pred for pred in preds if pred not in preds_dom_by_node]

        assert preds_dom_by_node
        assert preds_not_dom_by_node

        _l.debug(
            "Dominating predecessors: %s, non-dominating predecessors: %s",
            preds_dom_by_node,
            preds_not_dom_by_node,
        )

        # add the duplicated node into both the local graph and the full graph
        for pred in preds_not_dom_by_node:
            g.remove_edge(pred, nn)
            g.add_edge(pred, dup_node)
            if full_g is not None:
                full_g.remove_edge(pred, nn)
                full_g.add_edge(pred, dup_node)

        succs = list(g.successors(nn))
        for succ in succs:
            g.add_edge(dup_node, succ)

        if full_g is not None:
            succs = list(full_g.successors(nn))
            for succ in succs:
                full_g.add_edge(dup_node, succ)

    @staticmethod
    def _find_nodes_between(g: networkx.DiGraph, start_node: Any, end_node: Any) -> List[Any]:
        nodes_in_between = []
        visited = {start_node}

        queue = [start_node]
        while queue:
            node = queue.pop(0)
            if node is end_node:
                continue
            for succ in g.successors(node):
                if succ not in visited and succ is not end_node:
                    visited.add(succ)
                    queue.append(succ)
                    nodes_in_between.append(succ)

        return nodes_in_between

    @staticmethod
    def idoms_and_ipostdoms(graph: networkx.DiGraph, head: Any, end: Any) -> Tuple[Dict, Dict]:
        inverted_g = networkx.DiGraph()
        inverted_g.add_nodes_from(graph)
        inverted_g.add_edges_from([(dst, src) for src, dst in graph.edges])
        ipostdoms = networkx.immediate_dominators(inverted_g, end)

        idoms = networkx.immediate_dominators(graph, head)

        return idoms, ipostdoms
