# pylint:disable=line-too-long,import-outside-toplevel,import-error,multiple-statements,too-many-boolean-expressions
from typing import List, Dict, Tuple, Union, Set, Any, DefaultDict, Optional, TYPE_CHECKING
from collections import defaultdict
import logging

import networkx

import claripy
from ailment.block import Block
from ailment.statement import ConditionalJump, Jump
from ailment.expression import Const, UnaryOp

from ....knowledge_plugins.cfg import IndirectJumpType
from ....utils.graph import dominates, inverted_idoms, to_acyclic_graph
from ...cfg.cfg_utils import CFGUtils
from ..sequence_walker import SequenceWalker
from ..condition_processor import ConditionProcessor
from ..utils import remove_last_statement, extract_jump_targets, switch_extract_cmp_bounds, is_empty_node
from .structurer_nodes import ConditionNode, SequenceNode, LoopNode, ConditionalBreakNode, BreakNode, ContinueNode, \
    BaseNode, MultiNode, SwitchCaseNode, IncompleteSwitchCaseNode, EmptyBlockNotice
from .structurer_base import StructurerBase

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

l = logging.getLogger(__name__)
_DEBUG = False


class PhoenixStructurer(StructurerBase):
    """
    Structure a region using a structuring algorithm that is similar to the one in Phoenix decompiler (described in the
    "phoenix decompiler" paper). Note that this implementation has quite a few improvements over the original described
    version and *should not* be used to evaluate the performance of the original algorithm described in that paper.
    """
    def __init__(self, region, parent_map=None, condition_processor=None, func: Optional['Function']=None,
                 case_entry_to_switch_head: Optional[Dict[int,int]]=None, parent_region=None, improve_structurer=True):
        super().__init__(region, parent_map=parent_map, condition_processor=condition_processor, func=func,
                         case_entry_to_switch_head=case_entry_to_switch_head, parent_region=parent_region,
                         improve_structurer=improve_structurer)

        # whitelist certain edges. removing these edges will destroy critical schemas, which will impact future
        # structuring cycles.
        # the set is populated during the analysis. _last_resort_refinement() will ensure not to remove any edges
        # who fall into these sets.
        self.whitelist_edges: Set[Tuple[int,int]] = set()

        self._phoenix_improved = self._improve_structurer
        self._edge_virtualization_hints = [ ]

        self._analyze()

    def _analyze(self):
        # iterate until there is only one node in the region

        if _DEBUG and len(list(networkx.connected_components(networkx.Graph(self._region.graph)))) > 1:
            l.error("Incorrect region graph (with more than one connected component). Investigate.")
            import ipdb; ipdb.set_trace()

        has_cycle = self._has_cycle()

        # special handling for single-node loops
        if len(self._region.graph.nodes) == 1 and has_cycle:
            self._analyze_cyclic()

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
                        if self._region.head not in self._region.graph:
                            # update the loop head
                            self._region.head = next(iter(node for node in self._region.graph.nodes
                                                          if node.addr == self._region.head.addr))
                        has_cycle = self._has_cycle()
                        continue
                has_cycle = self._has_cycle()

            if not progressed:
                l.debug("No progress is made. Enter last resort refinement.")
                removed_edge = self._last_resort_refinement(
                    self._region.head,
                    self._region.graph,
                    self._region.graph_with_successors if self._region.graph_with_successors is not None
                    else networkx.DiGraph(self._region.graph),
                )
                if not removed_edge:
                    # cannot make any progress in this region. return the subgraph directly
                    break

        if len(self._region.graph.nodes) == 1:
            # successfully structured
            self.result = next(iter(self._region.graph.nodes))
        else:
            self.result = None  # the actual result is in self._region.graph and self._region.graph_with_successors

    def _analyze_cyclic(self) -> bool:
        any_matches = False
        acyclic_graph = to_acyclic_graph(self._region.graph, loop_heads=[self._region.head])
        for node in list(reversed(CFGUtils.quasi_topological_sort_nodes(acyclic_graph))):
            if node not in self._region.graph:
                continue
            matched = self._match_cyclic_schemas(
                node,
                self._region.head,
                self._region.graph,
                self._region.graph_with_successors
                if self._region.graph_with_successors is not None
                else networkx.DiGraph(self._region.graph)
            )
            l.debug("... matching cyclic schemas: %s at %r", matched, node)
            any_matches |= matched
            if _DEBUG and len(list(networkx.connected_components(networkx.Graph(self._region.graph)))) > 1:
                l.error("Removed incorrect edges. Investigate.")
                import ipdb; ipdb.set_trace()
        return any_matches

    def _match_cyclic_schemas(self, node, head, graph, full_graph) -> bool:
        matched, loop_node = self._match_cyclic_while(node, head, graph, full_graph)
        if matched:
            if len(self._region.successors) == 1:
                # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
                self._rewrite_conditional_jumps_to_breaks(loop_node.sequence_node,
                                                          [ succ.addr for succ in self._region.successors ])
                # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
                self._rewrite_jumps_to_continues(loop_node.sequence_node)
            return True

        matched, loop_node = self._match_cyclic_dowhile(node, head, graph, full_graph)
        if matched:
            if len(self._region.successors) == 1:
                # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
                self._rewrite_conditional_jumps_to_breaks(loop_node.sequence_node,
                                                          [ succ.addr for succ in self._region.successors ])
                # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
                self._rewrite_jumps_to_continues(loop_node.sequence_node)
            return True

        matched = self._match_cyclic_natural_loop(node, head, graph, full_graph)
        return matched

    def _match_cyclic_while(self, node, head, graph, full_graph) -> Tuple[bool,Optional[LoopNode]]:
        succs = list(full_graph.successors(node))
        if len(succs) == 2:
            left, right = succs

            if full_graph.has_edge(right, node) and not full_graph.has_edge(left, node):
                left, right = right, left
            if left is node:
                # self loop
                # possible candidate
                _, head_block = self._find_node_going_to_dst(node, left)
                if head_block is None:
                    # it happens. for example:
                    # ## Block 4058c8
                    # 00 | 0x4058c8 | if ((rcx<8> == 0x0<64>)) { Goto 0x4058ca<64> } else { Goto None }
                    # 01 | 0x4058c8 | rcx<8> = (rcx<8> - 0x1<64>)
                    # 02 | 0x4058c8 | cc_dep1<8> = Conv(8->64, Load(addr=rsi<8>, size=1, endness=Iend_LE))
                    # 03 | 0x4058c8 | cc_dep2<8> = Conv(8->64, Load(addr=rdi<8>, size=1, endness=Iend_LE))
                    # 04 | 0x4058c8 | rdi<8> = (rdi<8> + d<8>)
                    # 05 | 0x4058c8 | rsi<8> = (rsi<8> + d<8>)
                    # 06 | 0x4058c8 | if ((Conv(64->8, cc_dep1<8>) == Conv(64->8, cc_dep2<8>))) { Goto 0x4058c8<64> } else { Goto None }
                    # 07 | 0x4058c8 | Goto(0x4058ca<64>)
                    _, head_block = self._find_node_going_to_dst(node, right)

                if (isinstance(head_block, MultiNode) and head_block.nodes
                        and isinstance(head_block.nodes[0], Block) and head_block.nodes[0].statements
                        and isinstance(head_block.nodes[0].statements[0], ConditionalJump)
                        or isinstance(head_block, Block)
                        and head_block.statements
                        and isinstance(head_block.statements[0], ConditionalJump)):
                    # otherwise it's a do-while loop
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, head_block, left)
                    edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, head_block, right)
                    if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                        # c = !c
                        self._remove_last_statement_if_jump(node)
                        seq_node = SequenceNode(node.addr, nodes=[node]) if not isinstance(node, SequenceNode) else node
                        loop_node = LoopNode('while', edge_cond_left, seq_node, addr=seq_node.addr)
                        self.replace_nodes(graph, node, loop_node, self_loop=False)
                        self.replace_nodes(full_graph, node, loop_node, self_loop=False)

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except(graph, loop_node, right)
                        self._remove_edges_except(full_graph, loop_node, right)

                        return True, loop_node
            elif full_graph.has_edge(left, node) \
                    and left is not head and full_graph.in_degree[left] == 1 and full_graph.out_degree[left] >= 1 \
                    and not full_graph.has_edge(right, node):

                if PhoenixStructurer._is_single_statement_block(node):
                    # the single-statement-block check is to ensure we don't execute any code before the conditional
                    # jump.
                    # otherwise it's a do-while loop or a natural loop

                    # possible candidate
                    _, head_block = self._find_node_going_to_dst(node, left)
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, head_block, left)
                    edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, head_block, right)
                    if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                        # c = !c
                        self._remove_last_statement_if_jump(node)
                        new_node = SequenceNode(node.addr, nodes=[node, left])
                        loop_node = LoopNode('while', edge_cond_left, new_node,
                                             addr=node.addr,  # FIXME: Use the instruction address of the last instruction in head
                                             )

                        # on the original graph
                        self.replace_nodes(graph, node, loop_node, old_node_1=left, self_loop=False)
                        # on the graph with successors
                        self.replace_nodes(full_graph, node, loop_node, old_node_1=left, self_loop=False)

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except(graph, loop_node, right)
                        self._remove_edges_except(full_graph, loop_node, right)

                        return True, loop_node

                elif self._phoenix_improved:
                    _, head_block = self._find_node_going_to_dst(node, left)
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, head_block, left)
                    edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, head_block, right)
                    if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                        # c = !c
                        self._remove_last_statement_if_jump(node)
                        cond_break = ConditionalBreakNode(node.addr, edge_cond_right, right.addr)
                        new_node = SequenceNode(node.addr, nodes=[node, cond_break, left])
                        loop_node = LoopNode('while', claripy.true, new_node,
                                             addr=node.addr,  # FIXME: Use the instruction address of the last instruction in head
                                             )

                        # on the original graph
                        self.replace_nodes(graph, node, loop_node, old_node_1=left, self_loop=False)
                        # on the graph with successors
                        self.replace_nodes(full_graph, node, loop_node, old_node_1=left, self_loop=False)

                        # ensure the loop has only one successor: the right node
                        self._remove_edges_except(graph, loop_node, right)
                        self._remove_edges_except(full_graph, loop_node, right)

                        return True, loop_node

        return False, None

    def _match_cyclic_dowhile(self, node, head, graph, full_graph) -> Tuple[bool,Optional[LoopNode]]:
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
                    _, succ_block = self._find_node_going_to_dst(succ, out_node)
                    edge_cond_succhead = self.cond_proc.recover_edge_condition(full_graph, succ_block, node)
                    edge_cond_succout = self.cond_proc.recover_edge_condition(full_graph, succ_block, out_node)
                    if claripy.is_true(claripy.Not(edge_cond_succhead) == edge_cond_succout):
                        # c = !c
                        self._remove_last_statement_if_jump(succ)
                        new_node = SequenceNode(node.addr, nodes=[node, succ])
                        loop_node = LoopNode('do-while', edge_cond_succhead, new_node,
                                             addr=node.addr,  # FIXME: Use the instruction address of the last instruction in head
                                             )

                        # on the original graph
                        self.replace_nodes(graph, node, loop_node, old_node_1=succ, self_loop=False)
                        # on the graph with successors
                        self.replace_nodes(full_graph, node, loop_node, old_node_1=succ, self_loop=False)

                        return True, loop_node
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
                    loop_node = LoopNode('do-while', edge_cond_head, seq_node, addr=seq_node.addr)

                    # on the original graph
                    self.replace_nodes(graph, node, loop_node, self_loop=False)
                    # on the graph with successors
                    self.replace_nodes(full_graph, node, loop_node, self_loop=False)

                    return True, loop_node
        return False, None

    def _match_cyclic_natural_loop(self, node, head, graph, full_graph) -> bool:

        if not (node is head or graph.in_degree[node] == 2):
            return False

        # check if there is a cycle that starts with head and ends with head
        next_node = node
        seq_node = SequenceNode(node.addr, nodes=[node])
        seen_nodes = set()
        while True:
            succs = list(full_graph.successors(next_node))
            if len(succs) != 1:
                return False
            next_node = succs[0]

            if next_node is node:
                break
            if next_node is not node and next_node in seen_nodes:
                return False

            seen_nodes.add(next_node)
            seq_node.nodes.append(next_node)

        loop_node = LoopNode('while', claripy.true, seq_node, addr=node.addr)

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

        return True

    def _refine_cyclic(self) -> bool:
        return self._refine_cyclic_core(self._region.head)

    def _refine_cyclic_core(self, loop_head) -> bool:
        graph: networkx.DiGraph = self._region.graph
        fullgraph: networkx.DiGraph = self._region.graph_with_successors
        if fullgraph is None:
            fullgraph = networkx.DiGraph(self._region.graph)

        # check if there is an out-going edge from the loop head
        head_succs = list(fullgraph.successors(loop_head))
        headgoing_edges: List[Tuple[BaseNode,BaseNode]] = [ ]
        outgoing_edges = [ ]
        successor = None  # the loop successor
        loop_type = None
        if len(head_succs) == 2 and any(head_succ not in graph for head_succ in head_succs):
            # make sure the head_pred is not already structured
            _, head_block_0 = self._find_node_going_to_dst(loop_head, head_succs[0])
            _, head_block_1 = self._find_node_going_to_dst(loop_head, head_succs[1])
            if head_block_0 is head_block_1 and head_block_0 is not None:
                # there is an out-going edge from the loop head
                # virtualize all other edges
                loop_type = "while"
                successor = next(iter(head_succ for head_succ in head_succs if head_succ not in graph))
                for node in graph.nodes:
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
                    # make sure the head_pred is not already structured
                    _, src_block_0 = self._find_node_going_to_dst(head_pred, head_pred_succs[0])
                    _, src_block_1 = self._find_node_going_to_dst(head_pred, head_pred_succs[1])
                    if src_block_0 is src_block_1 and src_block_0 is not None:
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
                    src_parent, src_block = self._find_node_going_to_dst(src, dst)
                    if src_block is None:
                        l.warning("Cannot find the source block jumping to the destination block at %#x. "
                                  "This is likely a bug elsewhere and needs to be addressed.", dst.addr)
                        # remove the edge anyway
                        fullgraph.remove_edge(src, dst)
                    elif not isinstance(src_block, (Block, MultiNode)):
                        # it has probably been structured into BreakNode or ConditionalBreakNode
                        # just remove the edge
                        fullgraph.remove_edge(src, dst)
                    else:
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
                        if claripy.is_true(break_cond):
                            break_node = BreakNode(
                                src_block.addr,  # FIXME: Use the instruction address of the last instruction
                                Const(None, None, successor.addr, self.project.arch.bits))
                        else:
                            break_node = ConditionalBreakNode(
                                src_block.addr,  # FIXME: Use the instruction address of the last instruction
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
            max_src_addr: int = max(src.addr for src, _ in headgoing_edges)
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
                cont_parent, cont_block = self._find_node_going_to_dst(src, loop_head)
                if cont_block is None:
                    # cont_block is not found. but it's ok. one possibility is that src is a jump table head with one
                    # case being the loop head. in such cases, we can just remove the edge.
                    if not src.addr in self.kb.cfgs['CFGFast'].jump_tables:
                        l.warning("_refine_cyclic_core: Cannot find the block going to loop head for edge %r -> %r."
                                  "Remove the edge anyway.",
                                  src, loop_head)
                    if graph.has_edge(src, loop_head):
                        graph.remove_edge(src, loop_head)
                    fullgraph.remove_edge(src, loop_head)
                else:
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
        l.debug("Matching acyclic schemas for region %r.", self._region)
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

        if _DEBUG and len(list(networkx.connected_components(networkx.Graph(self._region.graph)))) > 1:
            l.error("Got a wrong graph to work on. Investigate.")
            import ipdb; ipdb.set_trace()

        if graph.in_degree[head] == 0:
            acyclic_graph = graph
        else:
            acyclic_graph = networkx.DiGraph(graph)
            acyclic_graph.remove_edges_from(graph.in_edges(head))

            if _DEBUG and len(list(networkx.connected_components(networkx.Graph(acyclic_graph)))) > 1:
                l.error("Removed wrong edges. Investigate.")
                import ipdb; ipdb.set_trace()

        for node in list(reversed(CFGUtils.quasi_topological_sort_nodes(acyclic_graph))):
            if node not in graph:
                continue
            if graph.has_edge(node, head):
                # it's a back edge. skip
                continue
            l.debug("... matching acyclic switch-case constructs at %r", node)
            matched = self._match_acyclic_switch_cases(graph, full_graph, node)
            l.debug("... matched: %s", matched)
            any_matches |= matched
            if not matched:
                l.debug("... matching acyclic sequence at %r", node)
                matched = self._match_acyclic_sequence(graph, full_graph, node)
                l.debug("... matched: %s", matched)
                any_matches |= matched
            if not matched:
                l.debug("... matching acyclic ITE at %r", node)
                matched = self._match_acyclic_ite(graph, full_graph, node)
                l.debug("... matched: %s", matched)
                any_matches |= matched
            if self._phoenix_improved:
                if not matched:
                    l.debug("... matching acyclic ITE with short-circuit conditions at %r", node)
                    matched = self._match_acyclic_short_circuit_conditions(graph, full_graph, node)
                    l.debug("... matched: %s", matched)
                    any_matches |= matched
            if _DEBUG and len(list(networkx.connected_components(networkx.Graph(self._region.graph)))) > 1:
                l.error("Removed incorrect edges. Investigate.")
                import ipdb; ipdb.set_trace()
        return any_matches

    # switch cases

    def _match_acyclic_switch_cases(self, graph: networkx.DiGraph, full_graph: networkx.DiGraph, node) -> bool:
        if isinstance(node, (SwitchCaseNode, IncompleteSwitchCaseNode)):
            return False

        jump_tables = self.kb.cfgs['CFGFast'].jump_tables
        r = self._match_acyclic_switch_cases_address_loaded_from_memory(node, graph, full_graph, jump_tables)
        if not r:
            r = self._match_acyclic_switch_cases_address_computed(node, graph, full_graph, jump_tables)
        if not r:
            r = self._match_acyclic_incomplete_switch_cases(node, graph, full_graph, jump_tables)
        return r

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

        # populate whitelist_edges
        for case_node_addr in jump_table.jumptable_entries:
            self.whitelist_edges.add((node_a.addr, case_node_addr))
        self.whitelist_edges.add((node.addr, node_b_addr))
        self.whitelist_edges.add((node_a.addr, node_b_addr))

        # sanity check: case nodes are successors to node_a. all case nodes must have at most common one successor
        case_nodes = list(graph.successors(node_a))
        case_node_successors = set()
        for case_node in case_nodes:
            if case_node.addr in jump_table.jumptable_entries:
                succs = set(graph.successors(case_node))
                case_node_successors |= succs
        if len(case_node_successors) > 1:
            return False

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

        cases, node_default, to_remove = self._switch_build_cases(cmp_lb, jump_table.jumptable_entries, node, node_a,
                                                                  node_b_addr, graph, full_graph)

        if node_default is None:
            switch_end_addr = node_b_addr
        else:
            # we don't know what the end address of this switch-case structure is. let's figure it out
            switch_end_addr = None
            to_remove.add(node_default)

        to_remove.add(node_a)  # add node_a
        self._make_switch_cases_core(node, cmp_expr, cases, node_default, last_stmt.ins_addr, to_remove, graph,
                                     full_graph, node_a=node_a)

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

        jumptable_entries = jump_table.jumptable_entries

        if isinstance(last_stmt.false_target, Const):
            default_addr = last_stmt.false_target.value
        else:
            return False

        cases, node_default, to_remove = self._switch_build_cases(cmp_lb, jumptable_entries, node, node, default_addr,
                                                                  graph, full_graph)
        if node_default is None:
            # there must be a default case
            return False

        self._make_switch_cases_core(node, cmp_expr, cases, node_default, node.addr, to_remove, graph, full_graph)

        return True

    def _match_acyclic_incomplete_switch_cases(self, node, graph: networkx.DiGraph, full_graph: networkx.DiGraph,
                                               jump_tables: Dict) -> bool:
        # sanity checks
        if node.addr not in jump_tables:
            return False
        if isinstance(node, IncompleteSwitchCaseNode):
            return False
        if is_empty_node(node):
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

    def _switch_build_cases(self, cmp_lb, jumptable_entries, head_node, node_a: BaseNode, node_b_addr, graph,
                            full_graph) -> Tuple[Dict,Any,Set[Any]]:
        cases: Dict[Union[int,Tuple[int]],SequenceNode] = { }
        to_remove = set()

        # it is possible that the default node gets duplicated by other analyses and creates a default node (addr.a)
        # and a case node (addr.b). The addr.a node is a successor to the head node while the addr.b node is a
        # successor to node_a
        default_node_candidates = [ nn for nn in graph.nodes if nn.addr == node_b_addr ]
        if len(default_node_candidates) == 0:
            node_default: Optional[BaseNode] = None
        elif len(default_node_candidates) == 1:
            node_default: Optional[BaseNode] = default_node_candidates[0]
        else:
            node_default: Optional[BaseNode] = next(iter(nn for nn in default_node_candidates
                                                         if graph.has_edge(head_node, nn)), None)

        if node_default is not None and not isinstance(node_default, SequenceNode):
            # make the default node a SequenceNode so that we can insert Break and Continue nodes into it later
            new_node = SequenceNode(node_default.addr, nodes=[node_default])
            self.replace_nodes(graph, node_default, new_node)
            self.replace_nodes(full_graph, node_default, new_node)
            node_default = new_node

        # entry_addrs_set = set(jumptable_entries)
        converted_nodes: Dict[int,Any] = { }
        entry_addr_to_ids: DefaultDict[int,Set[int]] = defaultdict(set)

        # the default node might get duplicated (e.g., by EagerReturns). we detect if a duplicate of the default node
        # (node b) is a successor node of node a. we only skip those entries going to the default node if no duplicate
        # of default node exists in node a's successors.
        node_a_successors = list(graph.successors(node_a))
        if len(default_node_candidates) > 1:
            node_b_in_node_a_successors = any(nn for nn in node_a_successors if nn in default_node_candidates)
        else:
            # the default node is not duplicated
            node_b_in_node_a_successors = False

        for j, entry_addr in enumerate(jumptable_entries):
            if not node_b_in_node_a_successors and entry_addr == node_b_addr:
                # jump to default or end of the switch-case structure - ignore this case
                continue
            case_idx = cmp_lb + j

            entry_addr_to_ids[entry_addr].add(case_idx)
            if entry_addr in converted_nodes:
                continue

            entry_node = next(iter(nn for nn in node_a_successors if nn.addr == entry_addr), None)
            if entry_node is None:
                # Missing entries. They are probably *after* the entire switch-case construct. Replace it with an empty
                # Goto node.
                case_inner_node = Block(0, 0, statements=[
                    Jump(None, Const(None, None, entry_addr, self.project.arch.bits), ins_addr=0, stmt_idx=0)
                ])
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

        return cases, node_default, to_remove

    @staticmethod
    def _make_switch_cases_core(head, cmp_expr, cases, node_default, addr, to_remove: Set, graph: networkx.DiGraph,
                                full_graph: networkx.DiGraph, node_a=None):

        if node_default is not None:
            # the head no longer goes to the default case
            graph.remove_edge(head, node_default)
            full_graph.remove_edge(head, node_default)

        scnode = SwitchCaseNode(cmp_expr, cases, node_default, addr=addr)

        # insert the switch-case node to the graph
        other_nodes_inedges = [ ]
        out_edges = [ ]

        # remove all those entry nodes
        if node_default is not None:
            to_remove.add(node_default)

        for nn in to_remove:
            if nn is head:
                continue
            for src in graph.predecessors(nn):
                if not src in to_remove:
                    other_nodes_inedges.append((src, nn))
            for dst in full_graph.successors(nn):
                if dst not in to_remove:
                    out_edges.append((nn, dst))

        for nn in to_remove:
            graph.remove_node(nn)
            full_graph.remove_node(nn)

        graph.add_edge(head, scnode)
        full_graph.add_edge(head, scnode)

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

    # other acyclic schemas

    def _match_acyclic_sequence(self, graph, full_graph, start_node) -> bool:
        """
        Check if there is a sequence of regions, where each region has a single predecessor and a single successor.
        """
        succs = list(graph.successors(start_node))
        if len(succs) == 1:
            end_node = succs[0]
            if full_graph.out_degree[start_node] == 1 \
                    and full_graph.in_degree[end_node] == 1 \
                    and not full_graph.has_edge(end_node, start_node):
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
                    (not left_succs and not right_succs)
                    or (not left_succs and len(right_succs) == 1)
                    or (not right_succs and len(left_succs) == 1)
                    or (len(left_succs) == 1 and left_succs == right_succs)
            ):
                # potentially ITE
                jump_tables = self.kb.cfgs['CFGFast'].jump_tables

                if full_graph.in_degree[left] == 1 \
                        and full_graph.in_degree[right] == 1 \
                        and left.addr not in jump_tables \
                        and right.addr not in jump_tables:
                    edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                    edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                    if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                        # c = !c
                        new_cond_node = ConditionNode(start_node.addr, None, edge_cond_left, left, false_node=right)
                        # TODO: Remove the last statement of start_node
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
                jump_tables = self.kb.cfgs['CFGFast'].jump_tables

                if left.addr not in jump_tables \
                        and right.addr not in jump_tables:
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

            if len(right_succs) == 1 and right_succs[0] == left:
                # swap them
                left, right = right, left
                left_succs, right_succs = right_succs, left_succs
            if left in graph and len(left_succs) == 1 and left_succs[0] == right:
                # potentially If-Then
                if full_graph.in_degree[left] == 1 and full_graph.in_degree[right] == 2:
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
                if full_graph.in_degree[left] == 1 and full_graph.in_degree[right] == 2:
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

    def _match_acyclic_short_circuit_conditions(self, graph: networkx.DiGraph, full_graph: networkx.DiGraph,
                                                start_node) -> bool:
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
            cond_jump = ConditionalJump(
                None,
                self.cond_proc.convert_claripy_bool_ast(claripy.Or(claripy.Not(left_cond), left_right_cond)),
                Const(None, None, right.addr, self.project.arch.bits),
                Const(None, None, succ.addr, self.project.arch.bits),
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes(graph, start_node, new_node, old_node_1=left)
            self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)

            return True

        r = self._match_acyclic_short_circuit_conditions_type_b(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, right, right_left_cond, else_node = r
            # create the condition node
            cond_jump = ConditionalJump(
                None,
                self.cond_proc.convert_claripy_bool_ast(claripy.Or(left_cond, right_left_cond)),
                Const(None, None, left.addr, self.project.arch.bits),
                Const(None, None, else_node.addr, self.project.arch.bits),
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes(graph, start_node, new_node, old_node_1=right)
            self.replace_nodes(full_graph, start_node, new_node, old_node_1=right)

            return True

        r = self._match_acyclic_short_circuit_conditions_type_c(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, succ, left_succ_cond, right = r
            # create the condition node
            cond_jump = ConditionalJump(
                None,
                self.cond_proc.convert_claripy_bool_ast(claripy.And(left_cond, claripy.Not(left_succ_cond))),
                Const(None, None, right.addr, self.project.arch.bits),
                Const(None, None, succ.addr, self.project.arch.bits),
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes(graph, start_node, new_node, old_node_1=left)
            self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)
            return True

        r = self._match_acyclic_short_circuit_conditions_type_d(graph, full_graph, start_node)

        if r is not None:
            left, left_cond, right, right_left_cond, else_node = r
            # create the condition node
            cond_jump = ConditionalJump(
                None,
                self.cond_proc.convert_claripy_bool_ast(claripy.And(left_cond, right_left_cond)),
                Const(None, None, right.addr, self.project.arch.bits),
                Const(None, None, else_node.addr, self.project.arch.bits),
                ins_addr=start_node.addr,
                stmt_idx=0,
            )
            new_cond_node = Block(start_node.addr, None, statements=[cond_jump])
            self._remove_last_statement_if_jump(start_node)
            new_node = SequenceNode(start_node.addr, nodes=[start_node, new_cond_node])

            self.replace_nodes(graph, start_node, new_node, old_node_1=left)
            self.replace_nodes(full_graph, start_node, new_node, old_node_1=left)
            return True

        return False

    def _match_acyclic_short_circuit_conditions_type_a(self, graph, full_graph, start_node) -> Optional[Tuple]:  # pylint:disable=unused-argument

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
            if full_graph.in_degree[left] == 1 and full_graph.in_degree[right] >= 1:
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

    def _match_acyclic_short_circuit_conditions_type_b(self, graph, full_graph, start_node) -> Optional[Tuple]:  # pylint:disable=unused-argument

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
            if full_graph.in_degree[left] == 2 and full_graph.in_degree[right] == 1:
                edge_cond_left = self.cond_proc.recover_edge_condition(full_graph, start_node, left)
                edge_cond_right = self.cond_proc.recover_edge_condition(full_graph, start_node, right)
                if claripy.is_true(claripy.Not(edge_cond_left) == edge_cond_right):
                    # c0 = !c0
                    right_succs = list(full_graph.successors(right))
                    left_succs = list(full_graph.successors(left))
                    if len(right_succs) == 2 and left in right_succs:
                        else_node = next(iter(succ for succ in right_succs if succ is not left))
                        if len([ succ for succ in left_succs if succ is not else_node ]) == 1:
                            edge_cond_right_left = self.cond_proc.recover_edge_condition(full_graph, right, left)
                            edge_cond_right_else = self.cond_proc.recover_edge_condition(full_graph, right, else_node)
                            if claripy.is_true(claripy.Not(edge_cond_right_left) == edge_cond_right_else):
                                # c1 = !c1
                                return left, edge_cond_left, right, edge_cond_right_left, else_node
        return None

    def _match_acyclic_short_circuit_conditions_type_c(self, graph, full_graph, start_node) -> Optional[Tuple]:  # pylint:disable=unused-argument

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
            if full_graph.in_degree[left] == 1 and full_graph.in_degree[successor] >= 1:
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
                            edge_cond_left_successor = \
                                self.cond_proc.recover_edge_condition(full_graph, left, successor)
                            if claripy.is_true(claripy.Not(edge_cond_left_right) == edge_cond_left_successor):
                                # c1 = !c1
                                return left, edge_cond_left, successor, edge_cond_left_successor, right
        return None

    def _match_acyclic_short_circuit_conditions_type_d(self, graph, full_graph, start_node) -> Optional[Tuple]:  # pylint:disable=unused-argument

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
            if full_graph.in_degree[left] == 1 and full_graph.in_degree[else_node] >= 1:
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

    def _last_resort_refinement(self, head, graph: networkx.DiGraph, full_graph: Optional[networkx.DiGraph]) -> bool:

        if self._phoenix_improved:
            while self._edge_virtualization_hints:
                src, dst = self._edge_virtualization_hints.pop(0)
                if graph.has_edge(src, dst):
                    self._virtualize_edge(graph, full_graph, src, dst)
                    l.debug("last_resort: Removed edge %r -> %r (type 3)", src, dst)
                    return True

        # virtualize an edge to allow progressing in structuring
        all_edges_wo_dominance = [ ]  # to ensure determinism, edges in this list are ordered by a tuple of
                                      # (src_addr, dst_addr)
        secondary_edges = [ ]  # likewise, edges in this list are ordered by a tuple of (src_addr, dst_addr)
        other_edges = [ ]
        idoms = networkx.immediate_dominators(full_graph, head)
        if networkx.is_directed_acyclic_graph(full_graph):
            _, inv_idoms = inverted_idoms(full_graph)
            acyclic_graph = full_graph
        else:
            acyclic_graph = to_acyclic_graph(full_graph, loop_heads=[head])
            _, inv_idoms = inverted_idoms(acyclic_graph)
        for src, dst in acyclic_graph.edges:
            if src is dst:
                continue
            if not graph.has_edge(src, dst):
                # the edge might be from full_graph but not in graph
                continue
            if not dominates(idoms, src, dst) and not dominates(inv_idoms, dst, src):
                if (src.addr, dst.addr) not in self.whitelist_edges:
                    all_edges_wo_dominance.append((src, dst))
            elif not dominates(idoms, src, dst) and dominates(inv_idoms, dst, src):
                if (src.addr, dst.addr) not in self.whitelist_edges:
                    secondary_edges.append((src, dst))
            else:
                if (src.addr, dst.addr) not in self.whitelist_edges:
                    other_edges.append((src, dst))

        if all_edges_wo_dominance:
            all_edges_wo_dominance = list(sorted(all_edges_wo_dominance, key=lambda x: (x[0].addr, x[1].addr)))
            # virtualize the first edge
            src, dst = all_edges_wo_dominance[0]
            self._virtualize_edge(graph, full_graph, src, dst)
            l.debug("last_resort: Removed edge %r -> %r (type 1)", src, dst)
            return True

        if secondary_edges:
            secondary_edges = list(sorted(secondary_edges, key=lambda x: (x[0].addr, x[1].addr)))
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
                goto0_condition = UnaryOp(None, 'Not', last_stmt.condition)
                goto0_target = last_stmt.false_target
                goto1_target = last_stmt.true_target
            else:
                # this should not really happen...
                goto0_condition = None
                goto0_target = None
                goto1_target = None

            if goto0_condition is not None:
                goto0 = Block(last_stmt.ins_addr, 0, statements=[Jump(None, goto0_target,
                                                                      ins_addr=last_stmt.ins_addr,
                                                                      stmt_idx=0)])
                cond_node = ConditionNode(last_stmt.ins_addr, None, goto0_condition, goto0)
                goto1_node = Block(last_stmt.ins_addr, 0, statements=[Jump(None, goto1_target,
                                                                           ins_addr=last_stmt.ins_addr,
                                                                           stmt_idx=0)])
                remove_src_last_stmt = True
                new_src = SequenceNode(src.addr, nodes=[src, cond_node, goto1_node])
        elif isinstance(last_stmt, Jump):
            # do nothing
            pass
        else:
            # insert a Jump at the end
            stmt_addr = last_stmt.ins_addr if last_stmt is not None else src.addr
            goto_node = Block(stmt_addr, 0, statements=[
                Jump(None, Const(None, None, dst.addr, self.project.arch.bits), ins_addr=stmt_addr, stmt_idx=0)
            ])
            new_src = SequenceNode(src.addr, nodes=[src, goto_node])

        graph.remove_edge(src, dst)
        if new_src is not None:
            self.replace_nodes(graph, src, new_src)
        if full_graph is not None:
            full_graph.remove_edge(src, dst)
            if new_src is not None:
                self.replace_nodes(full_graph, src, new_src)
        if remove_src_last_stmt:
            remove_last_statement(src)

    @staticmethod
    def _find_node_going_to_dst(node: SequenceNode,
                                dst: Union[Block,BaseNode]) -> Tuple[Optional[BaseNode],Optional[Block]]:
        """

        :param node:
        :param dst_addr:
        :param dst_idx:
        :return:            A tuple of (parent node, node who has a successor of dst_addr)
        """

        dst_addr = dst.addr
        dst_idx = dst.idx if isinstance(dst, Block) else ...

        def _check(last_stmt):
            if isinstance(last_stmt, Jump) \
                    and isinstance(last_stmt.target, Const) \
                    and last_stmt.target.value == dst_addr \
                    and (dst_idx is ... or last_stmt.target_idx == dst_idx):
                return True
            elif isinstance(last_stmt, ConditionalJump):
                if isinstance(last_stmt.true_target, Const) and last_stmt.true_target.value == dst_addr:
                    return True
                elif isinstance(last_stmt.false_target, Const) and last_stmt.false_target.value == dst_addr:
                    return True
            return False

        def _handle_Block(block: Block, parent=None, **kwargs):  # pylint:disable=unused-argument
            if block.statements:
                first_stmt = block.statements[0]
                if _check(first_stmt):
                    walker.parent = parent
                    walker.block = block
                elif len(block.statements) > 1:
                    last_stmt = block.statements[-1]
                    if _check(last_stmt):
                        walker.parent = parent
                        walker.block = block

        def _handle_MultiNode(block: MultiNode, parent=None, **kwargs):  # pylint:disable=unused-argument
            if block.nodes and isinstance(block.nodes[-1], Block) and block.nodes[-1].statements:
                if _check(block.nodes[-1].statements[-1]):
                    walker.parent = parent
                    walker.block = block
                    return

        def _handle_BreakNode(break_node: BreakNode, parent=None, **kwargs):  # pylint:disable=unused-argument
            if isinstance(break_node.target, Const) and break_node.target.value == dst_addr:
                # FIXME: idx is ignored
                walker.parent = parent
                walker.block = break_node
                return

        walker = SequenceWalker(
            handlers={
                Block: _handle_Block,
                MultiNode: _handle_MultiNode,
                BreakNode: _handle_BreakNode,
            },
            update_seqnode_in_place=False
        )
        walker.parent = None
        walker.block = None
        walker.walk(node)
        return walker.parent, walker.block

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
    def _count_statements(node: Union[BaseNode,Block]) -> int:
        if isinstance(node, Block):
            return len(node.statements)
        elif isinstance(node, MultiNode):
            return sum(len(nn.statements) for nn in node.nodes)
        elif isinstance(node, SequenceNode):
            return sum(PhoenixStructurer._count_statements(nn) for nn in node.nodes)
        return 1

    @staticmethod
    def _is_single_statement_block(node: Union[BaseNode,Block]) -> bool:
        if isinstance(node, (Block, MultiNode, SequenceNode)):
            return PhoenixStructurer._count_statements(node) == 1
        return False

    @staticmethod
    def _remove_edges_except(graph: networkx.DiGraph, src, dst):
        for succ in list(graph.successors(src)):
            if succ is not src and succ is not dst:
                graph.remove_edge(src, succ)

    @staticmethod
    def _remove_last_statement_if_jump(node: BaseNode):
        try:
            last_stmts = ConditionProcessor.get_last_statements(node)
        except EmptyBlockNotice:
            return

        if len(last_stmts) == 1 and isinstance(last_stmts[0], (Jump, ConditionalJump)):
            remove_last_statement(node)
