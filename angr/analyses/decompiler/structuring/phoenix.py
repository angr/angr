from typing import Dict, Tuple, Optional, TYPE_CHECKING
from collections import defaultdict
import logging

import networkx

import claripy
from ailment.block import Block
from ailment.statement import ConditionalJump, Jump
from ailment.expression import Const

from ....utils.graph import dominates
from ...cfg.cfg_utils import CFGUtils
from ..sequence_walker import SequenceWalker
from ..utils import remove_last_statement
from .structurer_nodes import ConditionNode, SequenceNode, LoopNode, ConditionalBreakNode, BreakNode, ContinueNode, \
    BaseNode, MultiNode
from .structurer_base import StructurerBase

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

l = logging.getLogger(__name__)


class PhoenixStructurer(StructurerBase):
    """
    Structure a region using a structuring algorithm that is similar to the one in Phoenix decompiler (described in the
    "phoenix decompiler" paper). Note that this implementation has quite a few improvements over the original described
    version and *should not* be used to evaluate the performance of the original algorithm described in that paper.
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
            progressed = self._analyze_acyclic()
            if progressed and self._region.head not in self._region.graph:
                # update the head
                self._region.head = next(iter(node for node in self._region.graph.nodes
                                              if node.addr == self._region.head.addr))

            if has_cycle:
                progressed |= self._analyze_cyclic()
                if progressed:
                    if self._region.head not in self._region.graph:
                        # update the loop head
                        self._region.head = next(iter(node for node in self._region.graph.nodes
                                                      if node.addr == self._region.head.addr))
                else:
                    refined = self._refine_cyclic()
                    if refined:
                        continue
                has_cycle = self._has_cycle()

            if not progressed:
                import ipdb; ipdb.set_trace()
                self._last_resort_refinement(
                    self._region.head,
                    self._region.graph,
                    self._region.graph_with_successors,
                )

        assert len(self._region.graph.nodes) == 1
        self.result = next(iter(self._region.graph.nodes))

    def _analyze_cyclic(self) -> bool:
        return self._match_cyclic_schemas(
            self._region.head,
            self._region.graph,
            self._region.graph_with_successors
            if self._region.graph_with_successors is not None
            else networkx.DiGraph(self._region.graph)
        )

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

        loop_node = LoopNode('while', claripy.true, seq_node, addr=head.addr)

        # on the original graph
        for node in seq_node.nodes:
            if node is not head:
                graph.remove_node(node)
        self.replace_nodes(graph, head, loop_node)

        # on the graph with successors
        for node in seq_node.nodes:
            if node is not head:
                full_graph.remove_node(node)
        self.replace_nodes(full_graph, head, loop_node)

        return True

    def _refine_cyclic(self) -> bool:
        loop_head = self._region.head

        graph: networkx.DiGraph = self._region.graph
        fullgraph: networkx.DiGraph = self._region.graph_with_successors
        if fullgraph is None:
            fullgraph = networkx.DiGraph(self._region.graph)

        # check if there is an out-going edge from the loop head
        head_succs = list(fullgraph.successors(loop_head))
        headgoing_edges = [ ]
        outgoing_edges = [ ]
        successor = None  # the loop successor
        loop_type = None
        if len(head_succs) == 2 and any(head_succ not in graph for head_succ in head_succs):
            # there is an out-going edge from the loop head
            # virtualize all other edges
            loop_type = "while"
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
                    loop_type = "do-while"
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

        if loop_type is None:
            # natural loop. select *any* exit edge to determine the successor
            # well actually, to maintain determinism, we select the successor with the highest address
            successor_candidates = set()
            for node in graph.nodes:
                for succ in fullgraph.successors(node):
                    if succ not in graph:
                        successor_candidates.add(succ)
                    if loop_head is succ:
                        headgoing_edges.append((node, succ))
            if successor_candidates:
                successor_candidates = list(sorted(successor_candidates, key=lambda x: x.addr))
                successor = successor_candidates[0]
                # virtualize all other edges
                for succ in successor_candidates:
                    for pred in fullgraph.predecessors(succ):
                        outgoing_edges.append((pred, succ))

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
                    # keep in mind that at this point, src might have been structured already. this means the last
                    # block in src may not be the actual block that has a direct jump or a conditional jump to dst. as
                    # a result, we should walk all blocks in src to find the jump to dst, then extract the condition
                    # and augment the corresponding block with a ConditionalBreak.
                    src_parent, src_block = self._find_node_going_to_dst(src, dst.addr)
                    if src_block is not None:
                        break_cond = self.cond_proc.recover_edge_condition(fullgraph, src_block, dst)
                        has_continue = False
                        # at the same time, examine if there is an edge that goes from src to head. if so, we deal with
                        # it here as well.
                        head_going_edge = src, loop_head
                        if head_going_edge in headgoing_edges:
                            has_continue = True
                            headgoing_edges.remove(head_going_edge)

                        # create the ConditionBreak node
                        last_src_stmt = self.cond_proc.get_last_statement(src_block)
                        break_cond = self.cond_proc.recover_edge_condition(fullgraph, src_block, dst)
                        break_node = ConditionalBreakNode(
                            src.addr,  # FIXME: Use the instruction address of the last instruction
                            break_cond,
                            Const(None, None, successor.addr, self.project.arch.bits))
                        new_node = SequenceNode(src_block.addr, nodes=[src_block, break_node])
                        if has_continue:
                            if self.is_a_jump_target(last_src_stmt, loop_head.addr):
                                # instead of a conditional break node, we should insert a condition node instead
                                break_node = BreakNode(last_src_stmt.ins_addr,
                                                       Const(None, None, successor.addr, self.project.arch.bits))
                                cont_node = ContinueNode(last_src_stmt.ins_addr,
                                                         Const(None, None, loop_head.addr, self.project.arch.bits))
                                cond_node = ConditionNode(
                                    last_src_stmt.ins_addr,
                                    None,
                                    break_cond,
                                    break_node,
                                    false_node=cont_node
                                )
                                new_node.nodes[-1] = cond_node
                                graph.remove_edge(src, loop_head)
                                fullgraph.remove_edge(src, loop_head)
                            else:
                                # the last statement in src_block is not the conditional jump whose one branch goes to
                                # the loop head. it probably goes to another block that ends up going to the loop head.
                                # we don't handle it here.
                                pass

                        remove_last_statement(src_block)  # remove the last jump or conditional jump in src_block

                        fullgraph.remove_edge(src, dst)
                        if src_parent is not None:
                            # replace the node in its parent node
                            self.replace_node_in_node(src_parent, src_block, new_node)
                        else:
                            # directly replace the node in graph
                            self.replace_nodes(graph, src, new_node)
                            self.replace_nodes(fullgraph, src, new_node)

                else:
                    fullgraph.remove_edge(src, dst)

        if len(headgoing_edges) > 1:
            # convert all but one (the one with the highest address) head-going edges into continues
            max_src_addr = max(src.addr for src, _ in headgoing_edges)
            src_to_ignore = next(iter(src for src, _ in headgoing_edges if src.addr == max_src_addr))

            for src, _ in headgoing_edges:
                if src is src_to_ignore:
                    last_src_stm = self.cond_proc.get_last_statement(src)
                    if self.is_a_jump_target(last_src_stm, loop_head.addr):
                        # remove the last statement (which should be a Jump to the loop head)
                        remove_last_statement(src)
                    continue

                # due to prior structuring of sub regions, the continue node may already be a Jump statement deep in
                # src at this point. we need to find the Jump statement and replace it.
                cont_parent, cont_block = self._find_node_going_to_dst(src, loop_head.addr)
                if cont_block is not None:
                    # replace cont_block with a ContinueNode
                    graph.remove_edge(src, loop_head)
                    fullgraph.remove_edge(src, loop_head)

                    last_cont_stmt = self.cond_proc.get_last_statement(cont_block)
                    if cont_parent is not None:
                        remove_last_statement(cont_block)
                        cont_node = ContinueNode(last_cont_stmt.ins_addr,
                                                 Const(None, None, loop_head.addr, self.project.arch.bits))
                        new_node_ = SequenceNode(cont_block.addr, nodes=[cont_block, cont_node])
                        self.replace_node_in_node(cont_parent, cont_block, new_node_)
                    else:
                        cont_node = ContinueNode(last_cont_stmt.ins_addr,
                                                 Const(None, None, loop_head.addr, self.project.arch.bits))
                        new_node = SequenceNode(src.addr, nodes=[src, cont_node])
                        self.replace_nodes(graph, src, new_node)
                        self.replace_nodes(fullgraph, src, new_node)

        return bool(outgoing_edges or len(headgoing_edges) > 1)

    def _analyze_acyclic(self) -> bool:
        # match against known schemas
        return self._match_acyclic_schemas(
            self._region.graph,
            self._region.graph_with_successors
            if self._region.graph_with_successors is not None
            else networkx.DiGraph(self._region.graph),
            self._region.head,
        )

    def _match_acyclic_schemas(self, graph: networkx.DiGraph, full_graph: networkx.DiGraph, head) -> bool:
        # traverse the graph in reverse topological order
        any_matches = False

        if graph.in_degree[head] == 0:
            acyclic_graph = graph
        else:
            acyclic_graph = networkx.DiGraph(graph)
            acyclic_graph.remove_edges_from(graph.in_edges(head))

        for node in list(reversed(CFGUtils.quasi_topological_sort_nodes(acyclic_graph))):
            if node not in graph:
                continue
            if graph.has_edge(node, head):
                # it's a back edge. skip
                continue
            matched = self._match_acyclic_sequence(graph, full_graph, node)
            any_matches |= matched
            if not matched:
                matched = self._match_acyclic_ite(graph, full_graph, node)
                any_matches |= matched
        return any_matches

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

            if left in graph and right in graph and (
                    (not left_succs or not right_succs) or (len(left_succs) == 1 and left_succs == right_succs)
            ):
                # potentially ITE
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c = !c
                    new_cond_node = ConditionNode(start_node.addr, None, edge_cond_left, left, false_node=right)
                    # TODO: Remove the last statement of start_node
                    new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

                    # on the original graph
                    if right in graph:
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
            if left in graph and len(left_succs) == 1 and left_succs[0] == right:
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

            if right in graph and not left in graph:
                left, right = right, left
            if left in graph and not right in graph:
                # potentially If-then
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

    def _last_resort_refinement(self, head, graph: networkx.DiGraph, full_graph: Optional[networkx.DiGraph]):

        # virtualize an edge to allow progressing in structuring
        all_edges_wo_dominance = [ ]  # to ensure determinism, edges in this list are ordered by a tuple of
                                        # (src_addr, dst_addr)
        other_edges = [ ]
        idoms = networkx.immediate_dominators(graph, head)
        for src, dst in graph.edges:
            if src is dst:
                continue
            if not dominates(idoms, src, dst) and not dominates(idoms, dst, src):
                all_edges_wo_dominance.append((src, dst))
            else:
                other_edges.append((src, dst))

        if all_edges_wo_dominance:
            all_edges_wo_dominance = list(sorted(all_edges_wo_dominance, key=lambda x: (x[0].addr, x[1].addr)))

        if all_edges_wo_dominance:
            # virtualize the first edge
            src, dst = all_edges_wo_dominance[0]
            graph.remove_edge(src, dst)
            if full_graph is not None:
                full_graph.remove_edge(src, dst)
            return

        # we have to remove a normal edge... this should not happen though
        other_edges = list(sorted(other_edges, key=lambda x: (x[0].addr, x[1].addr)))
        if other_edges:
            src, dst = other_edges[0]
            graph.remove_edge(src, dst)
            if full_graph is not None:
                full_graph.remove_edge(src, dst)
            return

    @staticmethod
    def _find_node_going_to_dst(node: SequenceNode, dst_addr: int) -> Tuple[Optional[BaseNode],Optional[Block]]:
        """

        :param node:
        :param dst_addr:
        :return:            A tuple of (parent node, node who has a successor of dst_addr)
        """

        def _check(last_stmt):
            if isinstance(last_stmt, Jump) \
                    and isinstance(last_stmt.target, Const) \
                    and last_stmt.target.value == dst_addr:
                return True
            elif isinstance(last_stmt, ConditionalJump):
                if isinstance(last_stmt.true_target, Const) and last_stmt.true_target.value == dst_addr:
                    return True
                elif isinstance(last_stmt.false_target, Const) and last_stmt.false_target.value == dst_addr:
                    return True
            return False

        def _handle_Block(block: Block, parent=None, **kwargs):
            if block.statements:
                last_stmt = block.statements[-1]
                if _check(last_stmt):
                    walker.parent = parent
                    walker.block = block

        def _handle_MultiNode(block: MultiNode, parent=None, **kwargs):
            if block.nodes and block.nodes[-1].statements:
                if _check(block.nodes[-1].statements[-1]):
                    walker.parent = parent
                    walker.block = block
                    return

        walker = SequenceWalker(
            handlers={
                Block: _handle_Block,
                MultiNode: _handle_MultiNode,
            },
            update_seqnode_in_place=False
        )
        walker.parent = None
        walker.block = None
        walker.walk(node)
        return walker.parent, walker.block
