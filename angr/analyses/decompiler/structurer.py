# pylint:disable=multiple-statements,line-too-long,consider-using-enumerate
from typing import Dict, Set, Optional, Any, List, Union, Tuple, TYPE_CHECKING
import logging
import itertools
from collections import defaultdict

import networkx

import claripy
import ailment

from ...knowledge_plugins.cfg import IndirectJump, IndirectJumpType
from .. import Analysis, register_analysis
from ..cfg.cfg_utils import CFGUtils
from .region_identifier import GraphRegion
from .structurer_nodes import BaseNode, SequenceNode, CodeNode, ConditionNode, ConditionalBreakNode, LoopNode, \
    SwitchCaseNode, BreakNode, ContinueNode, EmptyBlockNotice, MultiNode, CascadingConditionNode
from .empty_node_remover import EmptyNodeRemover
from .jumptable_entry_condition_rewriter import JumpTableEntryConditionRewriter
from .condition_processor import ConditionProcessor
from .utils import remove_last_statement, extract_jump_targets, get_ast_subexprs, switch_extract_cmp_bounds, \
    insert_node
from .region_simplifiers.cascading_cond_transformer import CascadingConditionTransformer

if TYPE_CHECKING:
    from ...knowledge_plugins.functions import Function

l = logging.getLogger(name=__name__)


#
# The main analysis
#


class RecursiveStructurer(Analysis):
    """
    Recursively structure a region and all of its subregions.
    """
    def __init__(self, region, cond_proc=None, func: Optional['Function']=None):
        self._region = region
        self.cond_proc = cond_proc if cond_proc is not None else ConditionProcessor(self.project.arch)
        self.function = func

        self.result = None

        self._analyze()

    def _analyze(self):

        region = self._region.recursive_copy()
        self._case_entry_to_switch_head: Dict[int,int] = self._get_switch_case_entries()

        # visit the region in post-order DFS
        parent_map = { }
        stack = [ region ]

        while stack:
            current_region = stack[-1]

            has_region = False
            for node in networkx.dfs_postorder_nodes(current_region.graph, current_region.head):
                subnodes = [ ]
                if type(node) is GraphRegion:
                    if node.cyclic:
                        subnodes.append(node)
                    else:
                        subnodes.insert(0, node)
                    parent_map[node] = current_region
                    has_region = True
                stack.extend(subnodes)

            if not has_region:
                # pop this region from the stack
                stack.pop()

                # Get the parent region
                parent_region = parent_map.get(current_region, None)
                # structure this region
                st = self.project.analyses.Structurer(current_region, parent_map=parent_map,
                                                      condition_processor=self.cond_proc,
                                                      case_entry_to_switch_head=self._case_entry_to_switch_head,
                                                      func=self.function)
                # replace this region with the resulting node in its parent region... if it's not an orphan
                if not parent_region:
                    # this is the top-level region. we are done!
                    self.result = st.result
                    break

                self._replace_region(parent_region, current_region, st.result)

        # rewrite conditions in the result to remove all jump table entry conditions
        rewriter = JumpTableEntryConditionRewriter(set(itertools.chain(*self.cond_proc.jump_table_conds.values())))
        rewriter.walk(self.result)  # update SequenceNodes in-place

        # remove empty nodes (if any)
        self.result = EmptyNodeRemover(self.result).result

        # remove conditional jumps
        Structurer._remove_conditional_jumps(self.result)

        self.result = self.cond_proc.remove_claripy_bool_asts(self.result)

    @staticmethod
    def _replace_region(parent_region, sub_region, node):

        parent_region.replace_region(sub_region, node)

    def _get_switch_case_entries(self) -> Dict[int,int]:

        if self.function is None:
            return {}

        entries = {}
        func_block_addrs = self.function.block_addrs_set

        jump_tables = self.kb.cfgs['CFGFast'].jump_tables
        for jump_table_head_addr, jumptable in jump_tables.items():
            if jump_table_head_addr not in func_block_addrs:
                continue
            for entry_addr in jumptable.jumptable_entries:
                entries[entry_addr] = jump_table_head_addr

        return entries


class Structurer(Analysis):
    """
    Structure a region.

    The current function graph is provided so that we can detect certain edge cases, for example, jump table entries no
    longer exist due to empty node removal during structuring or prior steps.
    """
    def __init__(self, region, parent_map=None, condition_processor=None, func: Optional['Function']=None,
                 case_entry_to_switch_head: Optional[Dict[int,int]]=None):

        self._region: GraphRegion = region
        self._parent_map = parent_map
        self.function = func
        self._case_entry_to_switch_head = case_entry_to_switch_head

        self.cond_proc = condition_processor if condition_processor is not None \
            else ConditionProcessor(self.project.arch)

        # intermediate states
        self._new_sequences = [ ]

        self.result = None

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

    def _has_cycle(self):
        """
        Test if the region contains a cycle.

        :return: True if the region contains a cycle, False otherwise.
        :rtype: bool
        """

        return not networkx.is_directed_acyclic_graph(self._region.graph)

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
        structurer = self.project.analyses.Structurer(region, condition_processor=self.cond_proc, func=self.function)
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
        self._remove_redundant_jumps(seq)

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
    # Dealing with switch-case structures
    #

    def _make_switch_cases(self, seq):
        """
        Search for nodes that look like switch-cases and convert them to switch cases.

        :param seq:     The Sequence node.
        :return:        None
        """

        jump_tables = self.kb.cfgs['CFGFast'].jump_tables

        addr2nodes: Dict[int,Set[CodeNode]] = defaultdict(set)
        for node in seq.nodes:
            addr2nodes[node.addr].add(node)

        while True:
            for i in range(len(seq.nodes)):

                node = seq.nodes[i]

                # Jumptable_AddressLoadedFromMemory
                r = self._make_switch_cases_address_loaded_from_memory(seq, i, node, addr2nodes, jump_tables)
                if r:
                    # we found a node that looks like a switch-case. seq.nodes are changed. resume to find the next such
                    # case
                    break

                # Jumptable_AddressComputed
                r = self._make_switch_cases_address_computed(seq, i, node, addr2nodes, jump_tables)
                if r:
                    break

            else:
                # we did not find any node that looks like a switch-case. exit.
                break

    def _make_switch_cases_address_loaded_from_memory(self, seq, i, node, addr2nodes: Dict[int,Set[CodeNode]],
                                                      jump_tables: Dict[int,IndirectJump]) -> bool:
        """
        A typical jump table involves multiple nodes, which look like the following:

        Head:  s_50 = Conv(32->64, (Load(addr=stack_base-28, size=4, endness=Iend_LE) - 0x3f<32>))<8>
               if (((Load(addr=stack_base-28, size=4, endness=Iend_LE) - 0x3f<32>) <= 0x36<32>))
                    { Goto A<64> } else { Goto B<64> }

        A:     (with an indirect jump)
               Goto((Conv(32->64, Load(addr=(0x40964c<64> + (Load(addr=stack_base-80, size=8, endness=Iend_LE) Mul 0x4<8>)), size=4, endness=Iend_LE)) + 0x40964c<64>))

        B:     (the default case)
        """

        try:
            last_stmt = self.cond_proc.get_last_statement(node)
        except EmptyBlockNotice:
            return False
        successor_addrs = extract_jump_targets(last_stmt)
        if len(successor_addrs) != 2:
            return False

        for t in successor_addrs:
            if t in addr2nodes and t in jump_tables:
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

        # the real indirect jump
        if len(addr2nodes[target]) != 1:
            return False
        node_a = next(iter(addr2nodes[target]))
        # the default case
        node_b_addr = next(iter(t for t in successor_addrs if t != target))

        # Node A might have been structured. Un-structure it if that is the case.
        r, node_a = self._switch_unpack_sequence_node(seq, node_a, node_b_addr, jump_table, addr2nodes)
        if not r:
            return False

        # build switch-cases
        cases, node_default, to_remove = self._switch_build_cases(seq, cmp_lb, jump_table.jumptable_entries, i,
                                                                  node_b_addr, addr2nodes)
        if node_default is None:
            switch_end_addr = node_b_addr
        else:
            # we don't know what the end address of this switch-case structure is. let's figure it out
            switch_end_addr = None
        self._switch_handle_gotos(cases, node_default, switch_end_addr)

        self._make_switch_cases_core(seq, i, node, cmp_expr, cases, node_default, last_stmt.ins_addr, addr2nodes,
                                     to_remove, node_a=node_a, jumptable_addr=jump_table.addr)

        return True

    def _make_switch_cases_address_computed(self, seq, i, node, addr2nodes: Dict[int,Set[CodeNode]],
                                            jump_tables: Dict[int,IndirectJump]) -> bool:
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

        if not isinstance(last_stmt, ailment.Stmt.ConditionalJump):
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

        if isinstance(last_stmt.false_target, ailment.Expr.Const):
            default_addr = last_stmt.false_target.value
        else:
            return False

        cases, node_default, to_remove = self._switch_build_cases(seq, cmp_lb, jumptable_entries, default_addr, i,
                                                                  addr2nodes)
        if node_default is None:
            # there must be a default case
            return False

        self._make_switch_cases_core(seq, i, node, cmp_expr, cases, node_default, node.addr, addr2nodes, to_remove,
                                     jumptable_addr=jump_table.addr)

        return True

    def _make_switch_cases_core(self, seq, i, node, cmp_expr, cases, node_default, addr, addr2nodes, to_remove,
                                node_a=None, jumptable_addr=None):

        scnode = SwitchCaseNode(cmp_expr, cases, node_default, addr=addr)
        scnode = CodeNode(scnode, node.reaching_condition)

        # insert the switch-case node
        seq.insert_node(i + 1, scnode)
        # remove all those entry nodes
        if node_default is not None:
            to_remove.add(node_default)
        for node_ in to_remove:
            seq.remove_node(node_)
            addr2nodes[node_.addr].discard(node_)
            if not addr2nodes[node_.addr]:
                del addr2nodes[node_.addr]
        # remove the last statement in node
        remove_last_statement(node)
        if BaseNode.test_empty_node(node):
            seq.remove_node(node)
        if node_a is not None:
            # remove the last statement in node_a
            remove_last_statement(node_a)
            if BaseNode.test_empty_node(node_a):
                seq.remove_node(node_a)

        # rewrite conditions in the entire SequenceNode to remove jump table entry conditions
        rewriter = JumpTableEntryConditionRewriter(self.cond_proc.jump_table_conds[jumptable_addr])
        rewriter.walk(seq)  # update SequenceNodes in-place

    def _switch_unpack_sequence_node(self, seq: SequenceNode, node_a, node_b_addr: int, jumptable,
                                     addr2nodes: Dict[int,Set[CodeNode]]) -> Tuple[bool,Optional[CodeNode]]:
        """
        We might have already structured the actual body of the switch-case structure into a single Sequence node (node
        A). If that is the case, we un-structure the sequence node in this method.

        :param seq:                 The original Sequence node.
        :param node_a:              Node A.
        :param node_b_addr:         Address of node B.
        :param jumptable:           The corresponding jump table instance.
        :param addr2nodes:          A dict of addresses to their corresponding nodes in `seq`.
        :return:                    A boolean value indicating the result and an updated node_a. The boolean value is
                                    True if unpacking is not necessary or we successfully unpacked the sequence node,
                                    False otherwise.
        """

        jumptable_entries = jumptable.jumptable_entries

        if isinstance(node_a.node, SequenceNode):
            node_a_block_addrs = {n.addr for n in node_a.node.nodes}
        else:
            node_a_block_addrs = set()
        #
        # if that is the case, we un-structure it here
        if all(entry_addr in addr2nodes for entry_addr in jumptable_entries):
            return True, node_a
        elif self._switch_check_existence_of_jumptable_entries(jumptable_entries, node_a_block_addrs,
                                                               set(addr2nodes.keys()), node_a.addr, node_b_addr):
            # unpacking is needed
            for n in node_a.node.nodes:
                if isinstance(n, ConditionNode):
                    unpacked = self._switch_unpack_condition_node(n, jumptable)
                    if unpacked is None:
                        # unsupported. bail
                        return False, None
                    if n.addr in addr2nodes:
                        del addr2nodes[n.addr]
                    addr2nodes[n.addr].add(unpacked)
                    seq.add_node(unpacked)
                else:
                    the_node = CodeNode(n, None)
                    if n.addr in addr2nodes:
                        del addr2nodes[n.addr]
                    addr2nodes[n.addr].add(the_node)
                    seq.add_node(the_node)
            if node_a != addr2nodes[node_a.addr]:
                # update node_a
                seq.remove_node(node_a)
                node_a = next(iter(addr2nodes[node_a.addr]))
            return True, node_a

        # a jumptable entry is missing. it's very likely marked as the successor of the entire switch-case region. we
        # should have been handling it when dealing with multi-exit regions. ignore it here.
        return True, node_a

    def _switch_unpack_condition_node(self, cond_node: ConditionNode, jumptable) -> Optional[CodeNode]:
        """
        Unpack condition nodes by only removing one condition in the form of
        <Bool jump_table_402020 == 0x402ac4>.

        :param cond_node:   The condition node to unpack.
        :return:            The new unpacked node.
        """

        # FIXME: With the new jump table entry condition, this function is probably never used. Remove sequence node
        # FIXME: unpacking logic if that is the case.

        cond = cond_node.condition

        # look for a condition in the form of xxx == jump_target
        eq_condition = None
        remaining_cond = None
        true_node = None
        false_node = None

        jumptable_var = self.cond_proc.create_jump_target_var(jumptable.addr)

        if cond.op == "And":
            for arg in cond.args:
                if arg.op == "__eq__" \
                        and arg.args[0] is jumptable_var \
                        and isinstance(arg.args[1], claripy.Bits) \
                        and arg.args[1].concrete:
                    # found it
                    eq_condition = arg
                    remaining_cond = claripy.And(*(arg_ for arg_ in cond.args if arg_ is not arg))
                    true_node = cond_node.true_node
                    false_node = cond_node.false_node
                    break
            else:
                # unsupported
                return None
        elif cond.op == "__eq__":
            if cond.args[0] is jumptable_var \
                    and isinstance(cond.args[1], claripy.Bits) \
                    and cond.args[1].concrete:
                # found it
                eq_condition = cond
                true_node = cond_node.true_node
                false_node = cond_node.false_node
                remaining_cond = None
            else:
                # unsupported
                return None
        else:
            # unsupported
            return None

        if remaining_cond is None:
            if true_node is not None and false_node is None:
                return CodeNode(true_node, eq_condition)
            # unsupported
            return None

        return CodeNode(ConditionNode(cond_node.addr, claripy.true, remaining_cond, true_node, false_node=false_node),
                        eq_condition)

    def _switch_check_existence_of_jumptable_entries(self, jumptable_entries, node_a_block_addrs: Set[int],
                                                     known_node_addrs: Set[int], node_a_addr: int,
                                                     node_b_addr: int) -> bool:
        """
        Check if all entries in the given jump table exist in the given set of nodes of a SequenceNode.

        :param jumptable_entries:   Addresses of jump table entries.
        :param node_a_block_addrs:  A set of addresses for nodes that belong to Node A.
        :return:                    True if the check passes, False otherwise.
        """

        all_node_addrs = node_a_block_addrs | known_node_addrs | {node_b_addr}
        expected_node_a_addrs = set()
        for entry_addr in jumptable_entries:
            if entry_addr in all_node_addrs:
                expected_node_a_addrs.add(entry_addr)
                continue
            # the entry may go missing if the entire node has been folded into its successor node.
            # in this case, we check if (a) this entry node has only one successor, and (b) this successor exists in
            # seq_node_addrs.
            if self.function is not None:
                entry_node = self.function.get_node(entry_addr)
                if entry_node is not None:
                    successors = [ ]
                    for _, dst, data in self.function.graph.out_edges(entry_node, data=True):
                        if data.get("type", "transition") != "call":
                            successors.append(dst)
                    if len(successors) == 1:
                        # found the single successor
                        if successors[0].addr in all_node_addrs:
                            expected_node_a_addrs.add(successors[0].addr)
                            continue
            # it's also possible that this is just a jump that breaks out of the switch-case. we simply ignore it.
            continue

        # finally, make sure all expected nodes exist
        if node_a_block_addrs.issuperset((expected_node_a_addrs | {node_a_addr}) - {node_b_addr}):
            return True

        # not sure what is going on...
        return False

    def _switch_find_jumptable_entry_node(self, entry_addr: int, addr2nodes: Dict[int,Set[CodeNode]]) -> Optional[Any]:
        """
        Find the correct node for a given jump table entry address in addr2nodes.

        This method is needed because prior optimization steps may remove some blocks (e.g., empty blocks or blocks that
        only have branch instructions). If the given jump table entry address corresponds to a removed block, it will
        not be found inside addr2nodes dict. In such cases, we need to follow graph edges in the CFG and find the first
        block whose address is inside addr2nodes dict.

        :param entry_addr:  Address of the jump table entry.
        :return:            The correct node if we can find it, or None if we fail to find one.
        """

        if entry_addr in addr2nodes and len(addr2nodes[entry_addr]) == 1:
            return next(iter(addr2nodes[entry_addr]))
        # magic
        if self.function is None:
            return None

        addr = entry_addr
        node = self.function.get_node(addr)
        for _ in range(5):  # we try at most five steps
            if node is None:
                return None
            successors = [ ]
            for _, dst, data in self.function.graph.out_edges(node, data=True):
                if data.get('type', 'transition') != "call":
                    successors.append(dst)
            if len(successors) != 1:
                return None
            successor = successors[0]
            if successor.addr in addr2nodes:
                # found it!
                return next(iter(addr2nodes[successor.addr]))
            # keep looking
            node = successor
        return None

    def _switch_build_cases(self, seq: SequenceNode, cmp_lb: int, jumptable_entries: List[int], head_node_idx: int,
                            node_b_addr: int, addr2nodes: Dict[int,Set[CodeNode]]):
        """
        Discover all cases for the switch-case structure and build the switch-cases dict.

        :param seq:                 The original Sequence node.
        :param cmp_lb:              The lower bound of the jump table comparison.
        :param jumptable_entries:   Addresses of indirect jump targets in the jump table.
        :param head_node_addr:      The index of the head block of this jump table in `seq`.
        :param node_b_addr:         Address of node B. Potentially, node B is the default node.
        :param addr2nodes:          A dict of addresses to their corresponding nodes in `seq`.
        :return:
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

    @staticmethod
    def _switch_handle_gotos(cases, default, switch_end_addr):
        """
        For each case, convert the goto that goes to outside of the switch-case to a break statement.

        :param dict cases:              A dict of switch-cases.
        :param default:                 The default node.
        :param int|None node_b_addr:    Address of the end of the switch.
        :return:                        None
        """

        goto_addrs = defaultdict(int)

        def _find_gotos(block, **kwargs):  # pylint:disable=unused-argument
            if block.statements:
                stmt = block.statements[-1]
                if isinstance(stmt, ailment.Stmt.Jump):
                    targets = extract_jump_targets(stmt)
                    for t in targets:
                        goto_addrs[t] += 1

        if switch_end_addr is None:
            # we need to figure this out
            handlers = {
                ailment.Block: _find_gotos
            }

            walker = SequenceWalker(handlers=handlers)
            for case_node in cases.values():
                walker.walk(case_node)

            if not goto_addrs:
                # there is no Goto statement - perfect
                return
            switch_end_addr = sorted(goto_addrs.items(), key=lambda x: x[1], reverse=True)[0][0]

        # rewrite all _goto switch_end_addr_ to _break_

        def _rewrite_gotos(block, parent=None, index=0, label=None):  # pylint:disable=unused-argument
            if block.statements and parent is not None:
                stmt = block.statements[-1]
                if isinstance(stmt, ailment.Stmt.Jump):
                    targets = extract_jump_targets(stmt)
                    if len(targets) == 1 and next(iter(targets)) == switch_end_addr:
                        # add a new a break statement to its parent
                        break_node = BreakNode(stmt.ins_addr, switch_end_addr)
                        # insert node
                        insert_node(parent, index + 1, break_node, index)
                        # remove the last statement
                        block.statements = block.statements[:-1]

        handlers = {
            ailment.Block: _rewrite_gotos,
        }

        walker = SequenceWalker(handlers=handlers)
        for case_node in cases.values():
            walker.walk(case_node)

        if default is not None:
            walker.walk(default)

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

    #
    # Other methods
    #

    @staticmethod
    def _remove_redundant_jumps(seq):
        """
        Remove all redundant jumps.

        :param SequenceNode seq:    The SequenceNode instance to handle.
        :return:                    A processed SequenceNode.
        """

        def _handle_Sequence(node: SequenceNode, **kwargs):
            if len(node.nodes) > 1:
                for i in range(len(node.nodes) - 1):
                    this_node = node.nodes[i]
                    goto_stmt: Optional[ailment.Stmt.Jump] = None
                    if isinstance(this_node, ailment.Block) and \
                            this_node.statements and \
                            isinstance(this_node.statements[-1], ailment.Stmt.Jump):
                        goto_stmt: ailment.Stmt.Jump = this_node.statements[-1]
                    elif isinstance(this_node, MultiNode) and \
                            this_node.nodes and \
                            isinstance(this_node.nodes[-1], ailment.Block) and \
                            this_node.nodes[-1].statements and \
                            isinstance(this_node.nodes[-1].statements[-1], ailment.Stmt.Jump):
                        this_node = this_node.nodes[-1]
                        goto_stmt: ailment.Stmt.Jump = this_node.statements[-1]

                    if goto_stmt is not None:
                        next_node = node.nodes[i + 1]
                        if isinstance(goto_stmt.target, ailment.Expr.Const) and \
                                goto_stmt.target.value == next_node.addr:
                            # this goto is useless
                            this_node.statements = this_node.statements[:-1]

            return walker._handle_Sequence(node, **kwargs)

        def _handle_MultiNode(node: MultiNode, **kwargs):
            if len(node.nodes) > 1:
                for i in range(len(node.nodes) - 1):
                    this_node = node.nodes[i]
                    goto_stmt: Optional[ailment.Stmt.Jump] = None
                    if isinstance(this_node, ailment.Block) and \
                            this_node.statements and \
                            isinstance(this_node.statements[-1], ailment.Stmt.Jump):
                        goto_stmt: ailment.Stmt.Jump = this_node.statements[-1]
                    elif isinstance(this_node, MultiNode) and \
                            this_node.nodes and \
                            isinstance(this_node.nodes[-1], ailment.Block) and \
                            this_node.nodes[-1].statements and \
                            isinstance(this_node.nodes[-1].statements[-1], ailment.Stmt.Jump):
                        goto_stmt: ailment.Stmt.Jump = this_node.nodes[-1].statements[-1]
                        this_node = this_node.nodes[-1]

                    if goto_stmt is not None:
                        next_node = node.nodes[i + 1]
                        if isinstance(goto_stmt.target, ailment.Expr.Const) and \
                                goto_stmt.target.value == next_node.addr:
                            # this goto is useless
                            this_node.statements = this_node.statements[:-1]

            return walker._handle_MultiNode(node, **kwargs)

        handlers = {
            SequenceNode: _handle_Sequence,
            MultiNode: _handle_MultiNode,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.walk(seq)

        return seq

    @staticmethod
    def _remove_conditional_jumps_from_block(block, parent=None, index=0, label=None):  # pylint:disable=unused-argument
        block.statements = [stmt for stmt in block.statements
                            if not isinstance(stmt, ailment.Stmt.ConditionalJump)]

    @staticmethod
    def _remove_conditional_jumps(seq, follow_seq=True):
        """
        Remove all conditional jumps.

        :param SequenceNode seq:    The SequenceNode instance to handle.
        :return:                    A processed SequenceNode.
        """

        def _handle_Sequence(node, **kwargs):
            if not follow_seq and node is not seq:
                return None
            return walker._handle_Sequence(node, **kwargs)


        handlers = {
            SequenceNode: _handle_Sequence,
            ailment.Block: Structurer._remove_conditional_jumps_from_block,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.walk(seq)

        return seq

    def _rewrite_conditional_jumps_to_breaks(self, loop_node, successor_addrs):

        def _rewrite_conditional_jump_to_break(node: ailment.Block, parent=None, index=None, label=None,
                                               **kwargs):  # pylint:disable=unused-argument
            if not node.statements:
                return

            # stores all nodes that will replace the current AIL Block node
            new_nodes: List = [ ]
            last_nonjump_stmt_idx = 0

            # find all jump and indirect jump statements
            for stmt_idx, stmt in enumerate(node.statements):
                if not isinstance(stmt, (ailment.Stmt.ConditionalJump, ailment.Stmt.Jump)):
                    continue
                targets = extract_jump_targets(stmt)
                if any(target in successor_addrs for target in targets):
                    # This node has an exit to the outside of the loop
                    # create a break or a conditional break node
                    break_node = self._loop_create_break_node(stmt, successor_addrs)
                    # insert this node to the parent
                    if isinstance(parent, SwitchCaseNode) and index is None:
                        # the parent of the current node is not a container. insert_node() handles it for us.
                        insert_node(parent, None, break_node, index, label=label, insert_location="before")
                        # now remove the node from the newly created container
                        if label == "case":
                            # parent.cases[index] is a SequenceNode now
                            parent.cases[index].remove_node(node)
                        elif label == "default":
                            parent.default_node.remove_node(node)
                        else:
                            raise TypeError("Unsupported label %s." % label)
                    else:
                        # previous nodes
                        if stmt_idx > last_nonjump_stmt_idx:
                            # add a subset of the block to new_nodes
                            sub_block_statements = node.statements[last_nonjump_stmt_idx : stmt_idx]
                            new_sub_block = ailment.Block(sub_block_statements[0].ins_addr,
                                                          stmt.ins_addr - sub_block_statements[0].ins_addr,
                                                          statements=sub_block_statements,
                                                          idx=node.idx,
                                                          )
                            new_nodes.append(new_sub_block)
                        last_nonjump_stmt_idx = stmt_idx + 1

                        new_nodes.append(break_node)

            if new_nodes:
                if len(node.statements) - 1 > last_nonjump_stmt_idx:
                    # insert the last node
                    sub_block_statements = node.statements[last_nonjump_stmt_idx: ]
                    new_sub_block = ailment.Block(sub_block_statements[0].ins_addr,
                                                  node.addr + node.original_size - sub_block_statements[0].ins_addr,
                                                  statements=sub_block_statements,
                                                  idx=node.idx,
                                                  )
                    new_nodes.append(new_sub_block)

                # replace the original node with nodes in the new_nodes list
                for new_node in reversed(new_nodes):
                    insert_node(parent, index + 1, new_node, index)
                # remove the current node
                node.statements = [ ]

        handlers = {
            ailment.Block: _rewrite_conditional_jump_to_break,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.walk(loop_node)

    @staticmethod
    def _rewrite_jumps_to_continues(loop_seq):

        def _rewrite_jump_to_continue(node, parent=None, index=None, label=None, **kwargs):  # pylint:disable=unused-argument
            if not node.statements:
                return
            stmt = node.statements[-1]
            if isinstance(stmt, ailment.Stmt.Jump):
                targets = extract_jump_targets(stmt)
                if any(target == loop_seq.addr for target in targets):
                    # This node has an exit to the beginning of the loop
                    # create a continue node
                    continue_node = ContinueNode(stmt.ins_addr, loop_seq.addr)
                    # insert this node to the parent
                    insert_idx = None if index is None else index + 1
                    insert_loc = 'after'
                    insert_node(parent, insert_idx, continue_node, index, label=label, insert_location=insert_loc)
                    # remove this statement
                    node.statements = node.statements[:-1]

        handlers = {
            ailment.Block: _rewrite_jump_to_continue,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.walk(loop_seq)

    @staticmethod
    def _merge_conditional_breaks(seq):

        # Find consecutive ConditionalBreakNodes and merge their conditions

        def _handle_SequenceNode(seq_node, parent=None, index=0, label=None):  # pylint:disable=unused-argument
            new_nodes = []
            i = 0
            while i < len(seq_node.nodes):
                old_node = seq_node.nodes[i]
                if type(old_node) is CodeNode:
                    node = old_node.node
                else:
                    node = old_node
                new_node = None
                if isinstance(node, ConditionalBreakNode) and new_nodes:
                    prev_node = new_nodes[-1]
                    if type(prev_node) is CodeNode:
                        prev_node = prev_node.node
                    if isinstance(prev_node, ConditionalBreakNode):
                        # found them!
                        # pop the previously added node
                        if new_nodes:
                            new_nodes = new_nodes[:-1]
                        merged_condition = ConditionProcessor.simplify_condition(claripy.Or(node.condition,
                                                                                            prev_node.condition))
                        new_node = ConditionalBreakNode(node.addr,
                                                        merged_condition,
                                                        node.target
                                                        )
                        walker.merged = True
                else:
                    walker._handle(node, parent=seq_node, index=i)

                if new_node is not None:
                    new_nodes.append(new_node)
                else:
                    new_nodes.append(old_node)
                i += 1

            seq_node.nodes = new_nodes

        handlers = {
            SequenceNode: _handle_SequenceNode,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.merged = False  # this is just a hack
        walker.walk(seq)
        return walker.merged, seq

    def _merge_nesting_conditionals(self, seq):

        # find if(A) { if(B) { ... ] } and simplify them to if( A && B ) { ... }

        def _condnode_truenode_only(node):
            if type(node) is CodeNode:
                # unpack
                node = node.node
            if isinstance(node, ConditionNode) and \
                    node.true_node is not None and \
                    node.false_node is None:
                return True, node
            return False, None

        def _condbreaknode(node):
            if type(node) is CodeNode:
                # unpack
                node = node.node
            if isinstance(node, SequenceNode):
                if len(node.nodes) != 1:
                    return False, None
                node = node.nodes[0]
                return _condbreaknode(node)
            if isinstance(node, ConditionalBreakNode):
                return True, node
            return False, None

        def _handle_SequenceNode(seq_node, parent=None, index=0, label=None):  # pylint:disable=unused-argument
            i = 0
            while i < len(seq_node.nodes):
                node = seq_node.nodes[i]
                r, cond_node = _condnode_truenode_only(node)
                if r:
                    r, cond_node_inner = _condnode_truenode_only(cond_node.true_node)
                    if r:
                        # amazing!
                        merged_cond = ConditionProcessor.simplify_condition(
                            claripy.And(self.cond_proc.claripy_ast_from_ail_condition(cond_node.condition),
                                        cond_node_inner.condition))
                        new_node = ConditionNode(cond_node.addr,
                                                 None,
                                                 merged_cond,
                                                 cond_node_inner.true_node,
                                                 None
                                                 )
                        seq_node.nodes[i] = new_node
                        walker.merged = True
                        i += 1
                        continue
                    # else:
                    r, condbreak_node = _condbreaknode(cond_node.true_node)
                    if r:
                        # amazing!
                        merged_cond = ConditionProcessor.simplify_condition(
                            claripy.And(self.cond_proc.claripy_ast_from_ail_condition(cond_node.condition),
                                        condbreak_node.condition))
                        new_node = ConditionalBreakNode(condbreak_node.addr, merged_cond, condbreak_node.target)
                        seq_node.nodes[i] = new_node
                        walker.merged = True
                        i += 1
                        continue

                walker._handle(node, parent=seq_node, index=i)

                i += 1

        handlers = {
            SequenceNode: _handle_SequenceNode,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.merged = False  # this is just a hack
        walker.walk(seq)

        return walker.merged, seq

    @staticmethod
    def _merge_nodes(node_0, node_1):

        addr = node_0.addr if node_0.addr is not None else node_1.addr
        if isinstance(node_0, SequenceNode):
            if isinstance(node_1, SequenceNode):
                return SequenceNode(addr, nodes=node_0.nodes + node_1.nodes)
            else:
                return SequenceNode(addr, nodes=node_0.nodes + [ node_1 ])
        else:
            if isinstance(node_1, SequenceNode):
                return SequenceNode(addr, nodes=[node_0] + node_1.nodes)
            else:
                return SequenceNode(addr, nodes=[node_0, node_1])

    def _update_new_sequences(self, removed_sequences: Set[SequenceNode], replaced_sequences: Dict[SequenceNode,Any]):
        new_sequences = [ ]
        for new_seq_ in self._new_sequences:
            if new_seq_ not in removed_sequences:
                if new_seq_ in replaced_sequences:
                    replaced = replaced_sequences[new_seq_]
                    if isinstance(replaced, SequenceNode):
                        new_sequences.append(replaced)
                else:
                    new_sequences.append(new_seq_)
        self._new_sequences = new_sequences


register_analysis(RecursiveStructurer, 'RecursiveStructurer')
register_analysis(Structurer, 'Structurer')

# delayed import
from .sequence_walker import SequenceWalker
