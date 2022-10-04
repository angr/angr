from typing import Dict, Optional, TYPE_CHECKING
from collections import defaultdict
import logging

import networkx

import claripy
from ailment.expression import Const

from ...cfg.cfg_utils import CFGUtils
from .structurer_nodes import ConditionNode, SequenceNode, LoopNode, ConditionalBreakNode, BreakNode, ContinueNode
from .structurer_base import StructurerBase

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

l = logging.getLogger(__name__)


class PhoenixStructurer(StructurerBase):
    """
    Structure a region using a structuring algorithm that is similar to the one in Phoenix decompiler (described in the
    "phoenix decompiler" paper).
    """
    def __init__(self, region, parent_map=None, condition_processor=None, func: Optional['Function']=None,
                 case_entry_to_switch_head: Optional[Dict[int,int]]=None):
        super().__init__(region, parent_map=parent_map, condition_processor=condition_processor, func=func,
                         case_entry_to_switch_head=case_entry_to_switch_head)

        self._analyze()

    def _analyze(self):
        # iterate until there is only one node in the region

        has_cycle = self._has_cycle()
        while len(self._region.graph.nodes) > 1:
            self._analyze_acyclic()
            if has_cycle:
                matched = self._analyze_cyclic()
                if not matched:
                    refined = self._refine_cyclic()
                    if refined:
                        continue
                    self._last_resort_refinement()
                    # this is where we need to re-run region identifier!
                    raise NotImplementedError("Invoke region identifier again")
                has_cycle = self._has_cycle()

        self.result = next(iter(self._region.graph.nodes))

    def _analyze_cyclic(self) -> bool:
        return self._match_cyclic_schemas(self._region.head, self._region.graph, self._region.graph_with_successors)

    def _match_cyclic_schemas(self, head, graph, full_graph) -> bool:
        matched = self._match_cyclic_while(head, graph, full_graph)
        if not matched:
            matched = self._match_cyclic_dowhile(head, graph, full_graph)
        if not matched:
            matched = self._match_cyclic_natural_loop(head, graph, full_graph)
        return matched

    def _match_cyclic_while(self, head, graph, full_graph) -> bool:
        succs = list(full_graph.successors(head))
        if len(succs) == 2:
            left, right = succs

            if full_graph.has_edge(right, head) and not full_graph.has_edge(left, head):
                left, right = right, left
            if full_graph.has_edge(left, head) and full_graph.out_degree[left] == 1 \
                    and not full_graph.has_edge(right, head):
                # possible candidate
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, head, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, head, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c = !c
                    loop_node = LoopNode('while', edge_cond_left, left,
                                         addr=head.addr,  # FIXME: Use the instruction address of the last instruction in head
                                         )
                    new_node = SequenceNode(head.addr, nodes=[head, loop_node])

                    # on the original graph
                    self.replace_nodes(graph, head, new_node, old_node_1=left)
                    # on the graph with successors
                    self.replace_nodes(full_graph, head, new_node, old_node_1=left)

                    return True

        return False

    def _match_cyclic_dowhile(self, head, graph, full_graph) -> bool:
        succs = list(full_graph.successors(head))
        if len(succs) == 1:
            succ = succs[0]
            succ_succs = list(full_graph.successors(succ))
            if len(succ_succs) == 2 and head in succ_succs:
                succ_succs.remove(head)
                out_node = succ_succs[0]

                if full_graph.has_edge(succ, head) and not full_graph.has_edge(out_node, head):
                    # possible candidate
                    edge_cond_succhead = self.cond_proc.recover_edge_condition(full_graph, succ, head)
                    edge_cond_succout = self.cond_proc.recover_edge_condition(full_graph, succ, out_node)
                    if claripy.is_true(claripy.Not(edge_cond_succhead) == edge_cond_succout):
                        # c = !c
                        loop_node = LoopNode('do-while', edge_cond_succhead, succ,
                                             addr=head.addr,  # FIXME: Use the instruction address of the last instruction in head
                                             )
                        new_node = SequenceNode(head.addr, nodes=[head, loop_node])

                        # on the original graph
                        self.replace_nodes(graph, head, new_node, old_node_1=succ)
                        # on the graph with successors
                        self.replace_nodes(full_graph, head, new_node, old_node_1=succ)

                        return True
        elif len(succs) == 2 and head in succs:
            # head forms a self-loop
            succs.remove(head)
            succ = succs[0]
            if not full_graph.has_edge(succ, head):
                # possible candidate
                edge_cond_head = self.cond_proc.recover_edge_condition(full_graph, head, head)
                edge_cond_head_succ = self.cond_proc.recover_edge_condition(full_graph, head, succ)
                if claripy.is_true(claripy.Not(edge_cond_head) == edge_cond_head_succ):
                    # c = !c
                    loop_node = LoopNode('do-while', edge_cond_head, head,
                                         addr=head.addr)

                    # on the original graph
                    self.replace_nodes(graph, head, loop_node)
                    # on the graph with successors
                    self.replace_nodes(full_graph, head, loop_node)

                    return True
        return False

    def _match_cyclic_natural_loop(self, head, graph, full_graph) -> bool:

        # check if there is a cycle that starts with head and ends with head
        next_node = head
        seq_node = SequenceNode(head.addr, nodes=[head])
        seen_nodes = set()
        while True:
            succs = list(full_graph.successors(next_node))
            if len(succs) != 1:
                return False
            next_node = succs[0]

            if next_node is head:
                break
            if next_node is not head and next_node in seen_nodes:
                return False

            seen_nodes.add(next_node)
            seq_node.nodes.append(next_node)

        # on the original graph
        for node in seq_node.nodes:
            if node is not head:
                graph.remove_node(node)
        self.replace_nodes(graph, head, seq_node)

        # on the graph with successors
        for node in seq_node.nodes:
            if node is not head:
                graph.remove_node(node)
        self.replace_nodes(full_graph, head, seq_node)

        return True

    def _refine_cyclic(self) -> bool:
        loop_head = self._region.head

        graph = self._region.graph
        fullgraph = self._region.graph_with_successors

        # check if there is an out-going edge from the loop head
        head_succs = list(fullgraph.successors(loop_head))
        headgoing_edges = [ ]
        outgoing_edges = [ ]
        successor = None  # the loop successor
        if len(head_succs) == 2 and any(head_succ not in graph for head_succ in head_succs):
            # there is an out-going edge from the loop head
            # virtualize all other edges
            successor = next(iter(head_succ for head_succ in head_succs if head_succ not in graph))
            for node in graph.nodes:
                if node is loop_head:
                    continue
                succs = list(fullgraph.successors(node))
                if loop_head in succs:
                    headgoing_edges.append((node, loop_head))

                outside_succs = [succ for succ in succs if succ not in graph]
                for outside_succ in outside_succs:
                    outgoing_edges.append((node, outside_succ))

        # check if there is an out-going edge from the loop tail
        elif len(head_succs) == 1:
            head_preds = list(fullgraph.predecessors(loop_head))
            if len(head_preds) == 1:
                head_pred = head_preds[0]
                head_pred_succs = list(fullgraph.successors(head_pred))
                if len(head_pred_succs) == 2 and any(nn not in graph for nn in head_pred_succs):
                    # there is an out-going edge from the loop tail
                    # virtualize all other edges
                    successor = next(iter(nn for nn in head_pred_succs if nn not in graph))
                    for node in graph.nodes:
                        if node is head_pred:
                            continue
                        succs = list(fullgraph.successors(node))
                        if loop_head in succs:
                            headgoing_edges.append((node, loop_head))

                        outside_succs = [succ for succ in succs if succ not in graph]
                        for outside_succ in outside_succs:
                            outgoing_edges.append((node, outside_succ))

        if outgoing_edges:
            # convert all out-going edges into breaks (if there is a single successor) or gotos (if there are multiple
            # successors)
            if successor is None:
                successor_and_edgecounts = defaultdict(int)
                for _, dst in outgoing_edges:
                    successor_and_edgecounts[dst] += 1

                if len(successor_and_edgecounts) > 1:
                    # pick one successor with the highest edge count and (in case there are multiple successors with the
                    # same edge count) the lowest address
                    max_edgecount = max(successor_and_edgecounts.values())
                    successor_candidates = [nn for nn, edgecount in successor_and_edgecounts.items()
                                            if edgecount == max_edgecount]
                    successor = next(iter(sorted(successor_candidates, key=lambda x: x.addr)))
                else:
                    successor = next(iter(successor_and_edgecounts.keys()))

            for src, dst in outgoing_edges:
                if dst is successor:
                    break_cond = self.cond_proc.recover_edge_condition(fullgraph, src, dst)
                    break_node = ConditionalBreakNode(
                        src.addr,  # FIXME: Use the instruction address of the last instruction
                        break_cond,
                        successor.addr)
                    new_node = SequenceNode(src.addr, nodes=[src, break_node])

                    self.replace_nodes(graph, src, new_node)
                    fullgraph.remove_edge(src, dst)
                    self.replace_nodes(fullgraph, src, new_node)

                else:
                    fullgraph.remove_edge(src, dst)

        if len(headgoing_edges) > 1:
            # convert all but one (the one with the highest address) head-going edges into continues
            max_src_addr = max(src.addr for src, _ in headgoing_edges)
            src_to_ignore = next(iter(src for src, _ in headgoing_edges if src.addr == max_src_addr))

            for src, _ in headgoing_edges:
                if src is src_to_ignore:
                    continue
                cont_node = ContinueNode(src.addr, # FIXME
                                         Const(None, None, loop_head.addr, self.project.arch.bits))
                new_node = SequenceNode(src.addr, nodes=[src, cont_node])

                graph.remove_edge(src, loop_head)
                self.replace_nodes(graph, src, new_node)
                fullgraph.remove_edge(src, loop_head)
                self.replace_nodes(fullgraph, src, new_node)

        return bool(outgoing_edges or headgoing_edges)

    def _analyze_acyclic(self):
        # match against known schemas
        return self._match_acyclic_schemas(
            self._region.graph,
            self._region.graph_with_successors
            if self._region.graph_with_successors is not None
            else networkx.DiGraph(self._region.graph))

    def _match_acyclic_schemas(self, graph, full_graph):
        # traverse the graph in reverse topological order
        any_matches = False
        for node in list(reversed(CFGUtils.quasi_topological_sort_nodes(graph))):
            if node not in graph:
                continue
            matched = self._match_acyclic_sequence(graph, full_graph, node)
            any_matches |= matched
            if not matched:
                matched = self._match_acyclic_ite(graph, full_graph, node)
                any_matches |= matched

    def _match_acyclic_sequence(self, graph, full_graph, start_node) -> bool:
        """
        Check if there is a sequence of regions, where each region has a single predecessor and a single successor.
        """
        succs = list(full_graph.successors(start_node))
        if len(succs) == 1:
            end_node = succs[0]
            if full_graph.in_degree[end_node] == 1 and not full_graph.has_edge(end_node, start_node):
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
            left_succs = list(full_graph.successors(left))
            right_succs = list(full_graph.successors(right))

            if (not left_succs and not right_succs) or (len(left_succs) == 1 and left_succs == right_succs):
                # potentially ITE
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c = !c
                    new_cond_node = ConditionNode(start_node.addr, None, edge_cond_left, left, false_node=right)
                    # TODO: Remove the last statement of start_node
                    new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                    # on the original graph
                    graph.remove_node(right)
                    self.replace_nodes(graph, start_node, new_node, old_node_1=left)
                    # on the graph with successors
                    full_graph.remove_node(right)
                    self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)

                    return True

            if len(right_succs) == 1 and right_succs[0] == left:
                # swap them
                left, right = right, left
                left_succs, right_succs = right_succs, left_succs
            if len(left_succs) == 1 and left_succs[0] == right:
                # potentially If-Then
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c = !c
                    new_cond_node = ConditionNode(start_node.addr, None, edge_cond_left, left, false_node=None)
                    # TODO: Remove the last statement of start_node
                    new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                    # on the original graph
                    self.replace_nodes(graph, start_node, new_node, old_node_1=left)
                    # on the graph with successors
                    self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)

                    return True
        return False
