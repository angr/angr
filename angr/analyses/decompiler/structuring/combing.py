from typing import Dict, Optional, Any, Tuple, List, TYPE_CHECKING
from collections import defaultdict
import logging

import networkx

import ailment
from ailment.expression import Const
from ailment.statement import Jump
import claripy

from angr.utils.graph import dfs_back_edges, dominates, GraphUtils, dump_graph
from .structurer_base import StructurerBase, EmptyBlockNotice
from .structurer_nodes import BaseNode, MultiNode, SequenceNode, ConditionNode, LoopNode

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


_l = logging.getLogger(__name__)
_DEBUG = False

if _DEBUG:
    _l.setLevel(logging.DEBUG)


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

        self._analyze()

    def _analyze(self):
        has_cycle = self._preprocess()

        # at this point the graph is a directed acyclic graph.
        self._comb()

        # after combing, we can finally match without generating any goto statements!
        self.result = self._match_constructs(has_cycle)

        if self.result is None:
            dump_graph(self._region.graph, "D:/aa.dot")
            # breakpoint()

    def _preprocess(self) -> bool:
        """
        Make the graph a directed acyclic graph and get it ready for combing.
        """

        # TODO: Handle jump-table-based switch-case constructs

        has_cycles = self._has_cycle()

        if has_cycles:
            region_head, abnormal_retreating_edges = self._elect_region_head()

            if abnormal_retreating_edges:
                self._normalize_retreating_edges(region_head, abnormal_retreating_edges)

            self._region.head = region_head

            self._remove_retreating_edges(abnormal_retreating_edges)

        return has_cycles

    def _elect_region_head(self) -> Tuple[Any, List[Tuple[Any, Any]]]:
        """
        Find all retreating edges, and then return the node with the highest number of retreating edges as the
        destination node.

        This function is only called on cyclic graphs.

        :return:    The elected region head.
        """

        # find retreating edges
        retreating_edges = dfs_back_edges(self._region.graph, self._region.head)

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

        breakpoint()

    def _remove_retreating_edges(self, abnormal_retreating_edges: List[Tuple[Any, Any]]):
        """
        Remove all edges pointing to the head plus all abnormal retreating edges.

        :param abnormal_retreating_edges:
        :return:
        """

        normal_retreating_edges = [(src, dst) for src, dst in self._region.graph.edges if dst is self._region.head]

        for src, dst in normal_retreating_edges + abnormal_retreating_edges:
            self._region.graph.remove_edge(src, dst)

    def _comb(self):
        """
        At this point, the region graph is finally a directed acyclic graph. We comb it as described in the paper.

        :return:
        """

        g = networkx.DiGraph(self._region.graph)
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
        self._region.graph = g

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

        # find all immediate post dominators
        idoms, ipostdoms = self.idoms_and_ipostdoms(g, self._region.head, exit_node)
        combed = False

        for node in list(reversed(GraphUtils.quasi_topological_sort_nodes(g))):
            if node is dummy_exit_node:
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
                import random

                dummy = SequenceNode(node.addr, nodes=[], idx=random.randint(100, 10000))  # fixme: idx must be fresh
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
                    full_graph.in_degree[right] == 2
                    and left_succs == [right]
                    or full_graph.in_degree[right] == 1
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

    def _apply_node_duplication(self, g: networkx.DiGraph, full_g: networkx.DiGraph, idoms: Dict, head: Any, nn: Any):
        dup_node = self._duplicate_node(nn)

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
            full_g.remove_edge(pred, nn)
            full_g.add_edge(pred, dup_node)

        succs = list(g.successors(nn))
        for succ in succs:
            g.add_edge(dup_node, succ)

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
    def _duplicate_node(node: Any) -> Any:
        if isinstance(node, ailment.Block):
            new_node = node.copy()
            new_node.idx = 1 if new_node.idx is None else new_node.idx + 1
        elif isinstance(node, SequenceNode):
            new_node = node.copy()
            new_node.idx = 1 if new_node.idx is None else new_node.idx + 1
        elif isinstance(node, MultiNode):
            new_node = node.copy()
            new_node.idx = 1 if new_node.idx is None else new_node.idx + 1
        else:
            raise TypeError("Unexpected node type")

        return new_node

    @staticmethod
    def idoms_and_ipostdoms(graph: networkx.DiGraph, head: Any, end: Any) -> Tuple[Dict, Dict]:
        inverted_g = networkx.DiGraph()
        inverted_g.add_nodes_from(graph)
        inverted_g.add_edges_from([(dst, src) for src, dst in graph.edges])
        ipostdoms = networkx.immediate_dominators(inverted_g, end)

        idoms = networkx.immediate_dominators(graph, head)

        return idoms, ipostdoms
