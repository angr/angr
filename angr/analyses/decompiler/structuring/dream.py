# pylint:disable=multiple-statements,line-too-long,consider-using-enumerate
from typing import Dict, Set, Optional, Any, List, Union, Tuple, TYPE_CHECKING
import logging
from collections import defaultdict

import networkx

import claripy
import ailment

from ...cfg.cfg_utils import CFGUtils
from ..graph_region import GraphRegion
from ..empty_node_remover import EmptyNodeRemover
from ..jumptable_entry_condition_rewriter import JumpTableEntryConditionRewriter
from ..condition_processor import ConditionProcessor
from ..region_simplifiers.cascading_cond_transformer import CascadingConditionTransformer
from ..utils import extract_jump_targets, get_ast_subexprs
from .structurer_nodes import (SequenceNode, CodeNode, ConditionNode, ConditionalBreakNode, LoopNode, SwitchCaseNode,
    BreakNode, ContinueNode, MultiNode, CascadingConditionNode)
from .structurer_base import StructurerBase


if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

l = logging.getLogger(name=__name__)


#
# The main analysis
#


class DreamStructurer(StructurerBase):
    """
    Structure a region using a structuring algorithm that is similar to the one in Dream decompiler (described in the
    "no more gotos" paper). Note that this implementation has quite a few improvements over the original described
    version and *should not* be used to evaluate the performance of the original algorithm described in that paper.

    The current function graph is provided so that we can detect certain edge cases, for example, jump table entries no
    longer exist due to empty node removal during structuring or prior steps.
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
            self._analyze_cyclic()
        else:
            if has_cycle:
                l.critical("Region %r is supposed to be an acyclic region but there are cycles inside. This is usually "
                           "due to the existence of loop headers with more than one in-edges, which angr decompiler "
                           "does not support yet. The decompilation result will be wrong.", self._region)
            self._analyze_acyclic()

    def _analyze_cyclic(self):

        loop_head = self._region.head

        loop_subgraph = self._region.graph
        successors = self._region.successors

        assert len(successors) <= 1

        loop_node = self._make_endless_loop(loop_head, loop_subgraph, successors)

        loop_node = self._refine_loop(loop_node)

        seq = SequenceNode(loop_head.addr,
                           nodes=[ loop_node ] + [ succ for succ in successors if succ in self._region.graph ])

        self.result = seq

    def _analyze_acyclic(self):

        # let's generate conditions first
        self.cond_proc.recover_reaching_conditions(self._region, with_successors=True,
                                                   case_entry_to_switch_head=self._case_entry_to_switch_head)

        # make the sequence node and pack reaching conditions into CodeNode instances
        seq = self._make_sequence()

        self._new_sequences.append(seq)

        while self._new_sequences:
            seq_ = self._new_sequences.pop(0)
            if len(seq_.nodes) <= 1:
                continue
            self._structure_sequence(seq_)

        seq = EmptyNodeRemover(seq).result

        # unpack nodes and remove CodeNode wrappers
        seq = self._unpack_sequence(seq)

        self.result = seq

    def _find_loop_nodes_and_successors(self):

        graph = self._region.graph
        head = self._region.head

        # find initial loop nodes
        loop_nodes = None
        components = networkx.strongly_connected_components(graph)
        for component in components:
            if head in component:
                loop_nodes = component
                break
        if loop_nodes is None:
            # this should never happen - loop head always forms a cycle
            raise TypeError("A bug (impossible case) in the algorithm is triggered.")

        # extend loop nodes
        while True:
            loop_nodes_updated = False
            for loop_node in loop_nodes:
                for succ in graph.successors(loop_node):
                    if succ not in loop_nodes:
                        # determine if this successor's all predecessors are in the loop
                        predecessors = graph.predecessors(succ)
                        if all(pred in loop_nodes for pred in predecessors):
                            # yes!
                            loop_nodes.add(succ)
                            loop_nodes_updated = True
                            break
                if loop_nodes_updated:
                    break
            if not loop_nodes_updated:
                break

        # find loop nodes and successors
        loop_subgraph = networkx.subgraph(graph, loop_nodes)
        loop_node_addrs = set( node.addr for node in loop_subgraph )

        # Case A: The loop successor is inside the current region (does it happen at all?)
        loop_successors = set()

        for node, successors in networkx.bfs_successors(graph, head):
            if node.addr in loop_node_addrs:
                for suc in successors:
                    if suc not in loop_subgraph:
                        loop_successors.add(suc)

        # Case B: The loop successor is the successor to this region in the parent graph
        if not loop_successors and self._parent_map is not None:
            current_region = self._region
            parent_region = self._parent_map.get(current_region, None)
            while parent_region and not loop_successors:
                parent_graph = parent_region.graph
                for node, successors in networkx.bfs_successors(parent_graph, current_region):
                    if node.addr == current_region.addr:
                        for suc in successors:
                            if suc not in loop_subgraph:
                                loop_successors.add(suc)
                current_region = parent_region
                parent_region = self._parent_map.get(current_region, None)

        return loop_subgraph, loop_successors

    def _make_endless_loop(self, loop_head, loop_subgraph, loop_successors):

        loop_body = self._to_loop_body_sequence(loop_head, loop_subgraph, loop_successors)

        # create a while(true) loop with sequence node being the loop body
        loop_node = LoopNode('while', None, loop_body, addr=loop_head.addr)

        return loop_node

    def _refine_loop(self, loop_node):

        while True:
            # while
            r, loop_node = self._refine_loop_while(loop_node)
            if r: continue

            # do-while
            r, loop_node = self._refine_loop_dowhile(loop_node)
            if r: continue

            # no more changes
            break

        return loop_node

    @staticmethod
    def _refine_loop_while(loop_node):

        if loop_node.sort == 'while' and loop_node.condition is None and loop_node.sequence_node.nodes:
            # it's an endless loop
            first_node = loop_node.sequence_node.nodes[0]
            if type(first_node) is CodeNode:
                first_node = first_node.node
            if type(first_node) is ConditionalBreakNode:
                while_cond = ConditionProcessor.simplify_condition(claripy.Not(first_node.condition))
                new_seq = loop_node.sequence_node.copy()
                new_seq.nodes = new_seq.nodes[1:]
                new_loop_node = LoopNode('while', while_cond, new_seq, addr=loop_node.addr)

                return True, new_loop_node

        return False, loop_node

    @staticmethod
    def _refine_loop_dowhile(loop_node):

        if loop_node.sort == 'while' and loop_node.condition is None and loop_node.sequence_node.nodes:
            # it's an endless loop
            last_node = loop_node.sequence_node.nodes[-1]
            if type(last_node) is ConditionalBreakNode:
                while_cond = ConditionProcessor.simplify_condition(claripy.Not(last_node.condition))
                new_seq = loop_node.sequence_node.copy()
                new_seq.nodes = new_seq.nodes[:-1]
                new_loop_node = LoopNode('do-while', while_cond, new_seq)

                return True, new_loop_node

        return False, loop_node

    def _to_loop_body_sequence(self, loop_head, loop_subgraph, loop_successors):

        graph = self._region.graph_with_successors
        loop_region_graph = networkx.DiGraph()

        # TODO: Make sure the loop body has been structured

        queue = [ loop_head ]
        traversed = set()
        loop_successor_addrs = set(succ.addr for succ in loop_successors)
        replaced_nodes = {}
        outedges = [ ]

        while queue:
            node = queue[0]
            queue = queue[1:]

            loop_region_graph.add_node(node)
            traversed.add(node)

            successors_and_data = list(graph.out_edges(node, data=True))  # successors are all inside the current region

            for _, dst, edge_data in successors_and_data:
                # sanity check
                if dst.addr in loop_successor_addrs:
                    outedges.append((node, dst, edge_data))
                    continue
                if dst not in loop_subgraph and dst.addr not in loop_successor_addrs:
                    # what's this node?
                    l.error("Found a node that belongs to neither loop body nor loop successors. Something is wrong.")
                    # raise Exception()

                if replaced_nodes.get(dst, dst) is not loop_head:
                    loop_region_graph.add_edge(node, replaced_nodes.get(dst, dst), **edge_data)
                if dst in traversed or dst in queue:
                    continue
                queue.append(dst)

        # Create a graph region and structure it
        loop_region_graph_with_successors = networkx.DiGraph(loop_region_graph)
        loop_successors = set()  # update loop_successors with nodes in outedges
        for src, dst, edge_data in outedges:
            loop_region_graph_with_successors.add_edge(src, dst, **edge_data)
            loop_successors.add(dst)
        region = GraphRegion(loop_head, loop_region_graph, successors=None,
                             graph_with_successors=None, cyclic=False)
        structurer = self.project.analyses[DreamStructurer].prep()(region, condition_processor=self.cond_proc,
                                                                   func=self.function)
        seq = structurer.result

        # traverse this node and rewrite all conditional jumps that go outside the loop to breaks
        self._rewrite_conditional_jumps_to_breaks(seq, loop_successor_addrs)
        # traverse this node and rewrite all jumps that go to the beginning of the loop to continue
        self._rewrite_jumps_to_continues(seq)

        seq = self._remove_redundant_jumps(seq)
        seq = self._remove_conditional_jumps(seq)
        seq = EmptyNodeRemover(seq).result

        while True:
            r, seq = self._merge_conditional_breaks(seq)
            if r: continue
            r, seq = self._merge_nesting_conditionals(seq)
            if r: continue
            break

        seq = EmptyNodeRemover(seq).result

        return seq

    def _loop_create_break_node(self, last_stmt, loop_successor_addrs):

        # This node has an exit to the outside of the loop
        # add a break or a conditional break node
        new_node = None

        if type(last_stmt) is ailment.Stmt.Jump:
            # shrink the block to remove the last statement
            # self._remove_last_statement(node)
            # add a break
            new_node = BreakNode(last_stmt.ins_addr, last_stmt.target.value)
        elif type(last_stmt) is ailment.Stmt.ConditionalJump:
            # add a conditional break
            true_target_value = None
            false_target_value = None
            if last_stmt.true_target is not None:
                true_target_value = last_stmt.true_target.value
            if last_stmt.false_target is not None:
                false_target_value = last_stmt.false_target.value

            if (true_target_value is not None and true_target_value in loop_successor_addrs) and \
                    (false_target_value is None or false_target_value not in loop_successor_addrs):
                cond = last_stmt.condition
                target = last_stmt.true_target.value
                new_node = ConditionalBreakNode(
                    last_stmt.ins_addr,
                    self.cond_proc.claripy_ast_from_ail_condition(cond),
                    target
                )
            elif (false_target_value is not None and false_target_value in loop_successor_addrs) and \
                    (true_target_value is None or true_target_value not in loop_successor_addrs):
                cond = ailment.Expr.UnaryOp(last_stmt.condition.idx, 'Not', (last_stmt.condition))
                target = last_stmt.false_target.value
                new_node = ConditionalBreakNode(
                    last_stmt.ins_addr,
                    self.cond_proc.claripy_ast_from_ail_condition(cond),
                    target
                )
            elif (false_target_value is not None and false_target_value in loop_successor_addrs) and \
                    (true_target_value is not None and true_target_value in loop_successor_addrs):
                # both targets are pointing outside the loop
                # we should use just add a break node
                new_node = BreakNode(last_stmt.ins_addr, last_stmt.false_target.value)
            else:
                l.warning("None of the branches is jumping to outside of the loop")
                raise Exception()

        return new_node

    def _make_sequence(self):

        seq = SequenceNode(None)

        for node in CFGUtils.quasi_topological_sort_nodes(self._region.graph):
            seq.add_node(CodeNode(node, self.cond_proc.reaching_conditions.get(node, None)))

        if seq.nodes:
            seq.addr = seq.nodes[0].addr

        return seq

    @staticmethod
    def _unpack_sequence(seq):

        def _handle_Code(node, **kwargs):  # pylint:disable=unused-argument
            node = node.node
            return walker._handle(node)

        def _handle_Sequence(node, **kwargs):  # pylint:disable=unused-argument
            for i in range(len(node.nodes)):  # pylint:disable=consider-using-enumerate
                node.nodes[i] = walker._handle(node.nodes[i])
            return node

        def _handle_ConditionNode(node, **kwargs):  # pylint:disable=unused-argument
            if node.true_node is not None:
                node.true_node = walker._handle(node.true_node)
            if node.false_node is not None:
                node.false_node = walker._handle(node.false_node)
            return node

        def _handle_CascadingConditionNode(node: CascadingConditionNode, **kwargs):  # pylint:disable=unused-argument
            new_cond_and_nodes = [ ]
            for cond, child_node in node.condition_and_nodes:
                new_cond_and_nodes.append((cond, walker._handle(child_node)))
            node.condition_and_nodes = new_cond_and_nodes

            if node.else_node is not None:
                node.else_node = walker._handle(node.else_node)
            return node

        def _handle_SwitchCaseNode(node, **kwargs):  # pylint:disable=unused-argument
            for i in list(node.cases.keys()):
                node.cases[i] = walker._handle(node.cases[i])
            if node.default_node is not None:
                node.default_node = walker._handle(node.default_node)
            return node

        def _handle_Default(node, **kwargs):  # pylint:disable=unused-argument
            return node

        handlers = {
            CodeNode: _handle_Code,
            SequenceNode: _handle_Sequence,
            ConditionNode: _handle_ConditionNode,
            CascadingConditionNode: _handle_CascadingConditionNode,
            SwitchCaseNode: _handle_SwitchCaseNode,
            # don't do anything
            LoopNode: _handle_Default,
            ContinueNode: _handle_Default,
            ConditionalBreakNode: _handle_Default,
            BreakNode: _handle_Default,
            MultiNode: _handle_Default,
            ailment.Block: _handle_Default,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.walk(seq)

        return seq

    def _structure_sequence(self, seq):

        self._make_switch_cases(seq)

        # this is hackish...
        # seq.nodes = new_seq.nodes

        self._merge_same_conditioned_nodes(seq)
        self._structure_common_subexpression_conditions(seq)
        self._make_ites(seq)
        self._remove_all_jumps(seq)

        empty_node_remover = EmptyNodeRemover(seq)
        new_seq = empty_node_remover.result
        # update self._new_sequences
        self._update_new_sequences(set(empty_node_remover.removed_sequences), empty_node_remover.replaced_sequences)

        # we need to do it in-place
        seq.nodes = new_seq.nodes

        self._replace_complex_reaching_conditions(seq)
        self._make_condition_nodes(seq)
        self._make_cascading_condition_nodes(seq)

        while True:
            r, seq = self._merge_conditional_breaks(seq)
            if r: continue
            r, seq = self._merge_nesting_conditionals(seq)
            if r: continue
            break

    def _merge_same_conditioned_nodes(self, seq):

        # search for nodes with the same reaching condition and then merge them into one sequence node
        i = 0
        while i < len(seq.nodes) - 1:
            node_0 = seq.nodes[i]
            if not type(node_0) is CodeNode:
                i += 1
                continue
            rcond_0 = node_0.reaching_condition
            if rcond_0 is None:
                i += 1
                continue
            node_1 = seq.nodes[i + 1]
            if not type(node_1) is CodeNode:
                i += 1
                continue
            rcond_1 = node_1.reaching_condition
            if rcond_1 is None:
                i += 1
                continue
            r = claripy.simplify(rcond_0 == rcond_1)
            if claripy.is_true(r):
                # node_0 and node_1 should be put into the same sequence node
                new_node = CodeNode(
                    self._merge_nodes(node_0.node, node_1.node),
                    node_0.reaching_condition,
                )
                seq.nodes = seq.nodes[:i] + [new_node] + seq.nodes[i + 2:]
                continue
            i += 1

    #
    # Dealing with switch-cases
    #

    def _make_switch_cases_core(self, seq, i, node, cmp_expr, cases, node_default, addr, addr2nodes, to_remove,
                                node_a=None, jumptable_addr=None):
        super()._make_switch_cases_core(seq, i, node, cmp_expr, cases, node_default, addr, addr2nodes, to_remove,
                                        node_a=node_a, jumptable_addr=jumptable_addr)

        # rewrite conditions in the entire SequenceNode to remove jump table entry conditions
        rewriter = JumpTableEntryConditionRewriter(self.cond_proc.jump_table_conds[jumptable_addr])
        rewriter.walk(seq)  # update SequenceNodes in-place

    def _switch_build_cases(self, seq: SequenceNode, cmp_lb: int, jumptable_entries: List[int], head_node_idx: int,
                            node_b_addr: int, addr2nodes: Dict[int,Set[CodeNode]]) -> Tuple[Dict,Any,Any]:
        """
        Discover all cases for the switch-case structure and build the switch-cases dict.

        :param seq:                 The original Sequence node.
        :param cmp_lb:              The lower bound of the jump table comparison.
        :param jumptable_entries:   Addresses of indirect jump targets in the jump table.
        :param head_node_addr:      The index of the head block of this jump table in `seq`.
        :param node_b_addr:         Address of node B. Potentially, node B is the default node.
        :param addr2nodes:          A dict of addresses to their corresponding nodes in `seq`.
        :return:                    A tuple of (dict of cases, the default node if exists, nodes to remove).
        """

        cases: Dict[Union[int,Tuple[int]],SequenceNode] = { }
        to_remove = set()
        node_default = addr2nodes.get(node_b_addr, None)
        if node_default is not None:
            node_default = next(iter(node_default))

        entry_addrs_set = set(jumptable_entries)
        converted_nodes: Dict[int,Any] = { }
        entry_addr_to_ids = defaultdict(set)

        for j, entry_addr in enumerate(jumptable_entries):
            cases_idx = cmp_lb + j
            if entry_addr == node_b_addr:
                # jump to default or end of the switch-case structure - ignore this case
                continue

            entry_addr_to_ids[entry_addr].add(cases_idx)

            if entry_addr in converted_nodes:
                continue

            entry_node = self._switch_find_jumptable_entry_node(entry_addr, addr2nodes)
            if entry_node is None:
                # Missing entries. They are probably *after* the entire switch-case construct. Replace it with an empty
                # Goto node.
                case_inner_node = ailment.Block(0, 0, statements=[
                    ailment.Stmt.Jump(None, ailment.Expr.Const(None, None, entry_addr, self.project.arch.bits),
                                      ins_addr=0, stmt_idx=0)
                ])
                case_node = SequenceNode(0, nodes=[CodeNode(case_inner_node, claripy.true)])
                converted_nodes[entry_addr] = case_node
                continue

            case_node = SequenceNode(entry_node.addr, nodes=[CodeNode(entry_node.node, claripy.true)])
            to_remove.add(entry_node)
            entry_node_idx = seq.nodes.index(entry_node)

            if entry_node_idx <= head_node_idx:
                # it's jumping to a block that dominates the head. it's likely to be an optimized continue; statement
                # in a switch-case wrapped inside a while loop.
                # replace it with an empty Goto node
                case_inner_node = ailment.Block(0, 0, statements=[
                    ailment.Stmt.Jump(None, ailment.Expr.Const(None, None, entry_addr, self.project.arch.bits),
                                      ins_addr=0, stmt_idx=0)
                ])
                case_node = SequenceNode(0, nodes=[CodeNode(case_inner_node, claripy.true)])
                converted_nodes[entry_addr] = case_node
                continue

            # find nodes that this entry node dominates
            cond_subexprs = list(get_ast_subexprs(entry_node.reaching_condition))
            guarded_nodes = None
            for subexpr in cond_subexprs:
                guarded_node_candidates = self._nodes_guarded_by_common_subexpr(seq, subexpr, entry_node_idx + 1)
                if guarded_nodes is None:
                    guarded_nodes = set(node_ for _, node_, _ in guarded_node_candidates)
                else:
                    guarded_nodes = guarded_nodes.intersection(
                        set(node_ for _, node_, _ in guarded_node_candidates))

            if guarded_nodes is not None:
                # keep the topological order of nodes in Sequence node
                sorted_guarded_nodes = [node_ for node_ in seq.nodes[entry_node_idx + 1:] if node_ in guarded_nodes]
                for node_ in sorted_guarded_nodes:
                    if node_ is not entry_node and node_.addr not in entry_addrs_set:
                        # fix reaching condition
                        reaching_condition_subexprs = set(
                            ex for ex in get_ast_subexprs(node_.reaching_condition)).difference(set(cond_subexprs))
                        new_reaching_condition = claripy.And(*reaching_condition_subexprs)
                        new_node = CodeNode(node_.node, new_reaching_condition)
                        case_node.add_node(new_node)
                        to_remove.add(node_)

            # do we have a default node?
            case_last_stmt = self.cond_proc.get_last_statement(case_node)
            if isinstance(case_last_stmt, ailment.Stmt.Jump):
                targets = extract_jump_targets(case_last_stmt)
                if len(targets) == 1 and targets[0] == node_b_addr:
                    # jump to the default case is rare - it's more likely that there is no default for this
                    # switch-case struct
                    node_default = None

            converted_nodes[entry_addr] = case_node

        for entry_addr, converted_node in converted_nodes.items():
            cases_ids = entry_addr_to_ids[entry_addr]
            if len(cases_ids) == 1:
                cases[next(iter(cases_ids))] = converted_node
            else:
                cases[tuple(sorted(cases_ids))] = converted_node

            self._new_sequences.append(converted_node)

        return cases, node_default, to_remove

    #
    # Dealing with If-Then-Else structures
    #

    def _make_ites(self, seq):

        # search for a == ^a pairs

        while True:
            break_hard = False
            for i in range(len(seq.nodes)):
                node_0 = seq.nodes[i]
                if not type(node_0) is CodeNode:
                    continue
                rcond_0 = node_0.reaching_condition
                if rcond_0 is None:
                    continue
                if claripy.is_true(rcond_0) or claripy.is_false(rcond_0):
                    continue
                for j in range(i + 1, len(seq.nodes)):
                    node_1 = seq.nodes[j]
                    if not type(node_1) is CodeNode:
                        continue
                    if node_0 is node_1:
                        continue
                    rcond_1 = node_1.reaching_condition
                    if rcond_1 is None:
                        continue
                    cond_ = claripy.simplify(claripy.Not(rcond_0) == rcond_1)
                    if claripy.is_true(cond_):
                        # node_0 and node_1 should be structured using an if-then-else
                        self._make_ite(seq, node_0, node_1)
                        break_hard = True
                        break
                if break_hard:
                    break
            else:
                break

    def _structure_common_subexpression_conditions(self, seq):

        # use common subexpressions to structure nodes and create more if-then-else instances

        i = 0
        while i < len(seq.nodes) - 1:
            structured = False
            node_0 = seq.nodes[i]
            if not isinstance(node_0, CodeNode):
                i += 1
                continue
            rcond_0 = node_0.reaching_condition
            if rcond_0 is None:
                i += 1
                continue
            subexprs_0 = list(get_ast_subexprs(rcond_0))

            for common_subexpr in subexprs_0:
                if claripy.is_true(common_subexpr):
                    continue
                candidates = self._nodes_guarded_by_common_subexpr(seq, common_subexpr, i + 1)
                if candidates:
                    candidates.insert(0,
                                      (i, node_0, subexprs_0))
                    new_node = self._create_seq_node_guarded_by_common_subexpr(common_subexpr, candidates)
                    self._new_sequences.append(new_node)

                    # remove all old nodes and replace them with the new node
                    for idx, _, _ in candidates:
                        seq.nodes[idx] = None
                    seq.nodes[i] = CodeNode(new_node, common_subexpr)
                    seq.nodes = [ n for n in seq.nodes if n is not None ]
                    structured = True
                    break

            if not structured:
                i += 1

    @staticmethod
    def _nodes_guarded_by_common_subexpr(seq, common_subexpr, starting_idx):

        candidates = []

        if common_subexpr is claripy.true:
            return [ ]
        for j, node_1 in enumerate(seq.nodes[starting_idx:]):
            rcond_1 = getattr(node_1, 'reaching_condition', None)
            if rcond_1 is None:
                continue
            subexprs_1 = list(get_ast_subexprs(rcond_1))
            if any(subexpr_1 is common_subexpr for subexpr_1 in subexprs_1):
                # we found one!
                candidates.append((starting_idx + j, node_1, subexprs_1))

        return candidates

    @staticmethod
    def _create_seq_node_guarded_by_common_subexpr(common_subexpr, candidates):

        new_nodes = [ ]

        for _, node, subexprs in candidates:
            # :)
            new_subexprs = [ex for ex in subexprs if ex is not common_subexpr]
            new_node = CodeNode(
                node.node,
                claripy.And(*new_subexprs),
            )
            new_nodes.append(new_node)

        new_node = SequenceNode(None if not new_nodes else new_nodes[0].addr, nodes=new_nodes)
        return new_node

    def _replace_complex_reaching_conditions(self, seq: SequenceNode):
        for i in range(len(seq.nodes)):
            node = seq.nodes[i]

            if isinstance(node, CodeNode) and \
                    node.reaching_condition is not None and \
                    node.reaching_condition.op == "Or" and \
                    node.node in self.cond_proc.guarding_conditions:
                guarding_condition = self.cond_proc.guarding_conditions[node.node]
                # the op of guarding condition is always "Or"
                if len(guarding_condition.args) < len(node.reaching_condition.args) and \
                        guarding_condition.depth < node.reaching_condition.depth:
                    node.reaching_condition = guarding_condition

    def _make_condition_nodes(self, seq):

        # make all conditionally-reachable nodes ConditionNodes
        for i in range(len(seq.nodes)):
            node = seq.nodes[i]

            if isinstance(node, CodeNode):
                if isinstance(node.node, SequenceNode) and node.node not in self._new_sequences:
                    self._make_condition_nodes(node.node)

                if node.reaching_condition is not None and not claripy.is_true(node.reaching_condition):
                    if isinstance(node.node, ConditionalBreakNode):
                        # Put conditions together and simplify them
                        cond = claripy.And(node.reaching_condition, node.node.condition)
                        new_node = CodeNode(ConditionalBreakNode(node.node.addr, cond, node.node.target), None)
                    else:
                        new_node = ConditionNode(node.addr, None, node.reaching_condition, node,
                                                 None)
                    seq.nodes[i] = new_node

    @staticmethod
    def _make_cascading_condition_nodes(seq: SequenceNode):
        """
        Convert nested condition nodes into a CascadingConditionNode.
        """
        CascadingConditionTransformer(seq)

    def _make_ite(self, seq, node_0, node_1):

        # ensure order
        if node_0.addr > node_1.addr:
            node_0, node_1 = node_1, node_0

        node_0_pos = seq.node_position(node_0)
        node_1_pos = seq.node_position(node_1)
        pos = max(node_0_pos, node_1_pos)

        node_0_, node_1_ = node_0.copy(), node_1.copy()
        # clear their reaching conditions
        node_0_.reaching_condition = None
        node_1_.reaching_condition = None

        node_0_kids = self._nodes_guarded_by_common_subexpr(seq, node_0.reaching_condition, node_0_pos + 1)
        node_0_kids.insert(0, (node_0_pos, node_0_, [ node_0.reaching_condition ]))
        node_1_kids = self._nodes_guarded_by_common_subexpr(seq, node_1.reaching_condition, node_1_pos + 1)
        node_1_kids.insert(0, (node_1_pos, node_1_, [ node_1.reaching_condition ]))

        new_node_0 = self._create_seq_node_guarded_by_common_subexpr(node_0.reaching_condition,
                                                                     node_0_kids)
        new_node_1 = self._create_seq_node_guarded_by_common_subexpr(node_1.reaching_condition,
                                                                     node_1_kids)

        self._new_sequences.append(new_node_0)
        self._new_sequences.append(new_node_1)

        seq_addr = seq.addr

        # erase all nodes in the candidates
        for idx, _, _ in node_0_kids + node_1_kids:
            seq.nodes[idx] = None

        seq.insert_node(pos, ConditionNode(seq_addr, None, node_0.reaching_condition, new_node_0,
                                           new_node_1))
        seq.nodes = [ n for n in seq.nodes if n is not None ]


# delayed import
from ..sequence_walker import SequenceWalker  # pylint:disable=wrong-import-position
