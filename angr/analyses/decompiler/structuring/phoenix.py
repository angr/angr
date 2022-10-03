from typing import Dict, Optional, TYPE_CHECKING
import logging

import claripy

from ...cfg.cfg_utils import CFGUtils
from .structurer_nodes import ConditionNode, SequenceNode, LoopNode
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
        has_cycle = self._has_cycle()
        # sanity checks
        if self._region.cyclic:
            if not has_cycle:
                l.critical("Region %r is supposed to be a cyclic region but there is no cycle inside. This is usually "
                           "due to the existence of loop headers with more than one in-edges, which angr decompiler "
                           "does not support yet. The decompilation result will be wrong.", self._region)
            matched = self._analyze_cyclic()
            if not matched:
                self._refine_cyclic()
                matched = self._analyze_cyclic()
        else:
            if has_cycle:
                l.critical("Region %r is supposed to be an acyclic region but there are cycles inside. This is usually "
                           "due to the existence of loop headers with more than one in-edges, which angr decompiler "
                           "does not support yet. The decompilation result will be wrong.", self._region)
            self._analyze_acyclic()

    def _analyze_cyclic(self):
        self._match_cyclic_schemas(self._region.head, self._region.graph, self._region.graph_with_successors)
        assert len(self._region.graph.nodes) == 1
        self.result = next(iter(self._region.graph.nodes))

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
        if len(head_succs) > 1 and any(head_succ not in graph for head_succ in head_succs):
            # there is an out-going edge from the loop head
            # virtualize all other edges
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
        if len(head_succs) == 1:
            raise NotImplementedError()

    def _analyze_acyclic(self):
        # match against known schemas
        self._match_acyclic_schemas(self._region.graph, self._region.graph_with_successors)

        assert len(self._region.graph.nodes) == 1
        self.result = next(iter(self._region.graph.nodes))

    def _match_acyclic_schemas(self, graph, full_graph):
        # traverse the graph in reverse topological order
        any_matches = False
        for node in list(reversed(CFGUtils.quasi_topological_sort_nodes(graph))):
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
            if full_graph.in_degree[end_node] == 1:
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
