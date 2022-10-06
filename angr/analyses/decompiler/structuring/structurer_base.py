from typing import Optional, Dict, Set, List, Any, Union, Tuple, TYPE_CHECKING
from collections import defaultdict

import networkx

import ailment
import claripy

from ....knowledge_plugins.cfg import IndirectJump, IndirectJumpType
from ... import Analysis
from ..condition_processor import ConditionProcessor
from ..sequence_walker import SequenceWalker
from ..utils import extract_jump_targets, insert_node, switch_extract_cmp_bounds, remove_last_statement
from .structurer_nodes import MultiNode, SequenceNode, SwitchCaseNode, CodeNode, ConditionNode, ConditionalBreakNode, \
    ContinueNode, BaseNode, CascadingConditionNode, BreakNode, EmptyBlockNotice

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.analyses.decompiler.graph_region import GraphRegion


class StructurerBase(Analysis):
    """
    The base class for analysis passes that structures a region.

    The current function graph is provided so that we can detect certain edge cases, for example, jump table entries no
    longer exist due to empty node removal during structuring or prior steps.
    """
    def __init__(self, region, parent_map=None, condition_processor=None, func: Optional['Function']=None,
                 case_entry_to_switch_head: Optional[Dict[int,int]]=None):
        self._region: 'GraphRegion' = region
        self._parent_map = parent_map
        self.function = func
        self._case_entry_to_switch_head = case_entry_to_switch_head

        self.cond_proc = condition_processor if condition_processor is not None \
            else ConditionProcessor(self.project.arch)

        # intermediate states
        self._new_sequences = []

        self.result = None

    def _analyze(self):
        raise NotImplementedError()

    #
    # Basic structuring methods
    #

    def _structure_sequence(self, seq: SequenceNode):
        raise NotImplementedError()

    #
    # Util methods
    #

    def _has_cycle(self):
        """
        Test if the region contains a cycle.

        :return: True if the region contains a cycle, False otherwise.
        :rtype: bool
        """

        return not networkx.is_directed_acyclic_graph(self._region.graph)

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
            ailment.Block: StructurerBase._remove_conditional_jumps_from_block,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.walk(seq)

        return seq


    @staticmethod
    def _remove_all_jumps(seq):
        """
        Remove all constant jumps.

        :param SequenceNode seq:    The SequenceNode instance to handle.
        :return:                    A processed SequenceNode.
        """

        def _handle_Block(node: ailment.Block, **kwargs):  # pylint:disable=unused-argument
            if node.statements \
                    and isinstance(node.statements[-1], ailment.Stmt.Jump) \
                    and isinstance(node.statements[-1].target, ailment.Expr.Const):
                # remove the jump
                node.statements = node.statements[:-1]

            return node

        handlers = {
            ailment.Block: _handle_Block,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.walk(seq)

        return seq

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
                        insert_node(parent, index, break_node, index, label=label)
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
                    insert_node(parent, index + 1, continue_node, index, label=label)  # insert after
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

        raise NotImplementedError("Please implement _switch_build_cases in your own Structurer class")

    @staticmethod
    def _switch_handle_gotos(cases, default, switch_end_addr):
        """
        For each case, convert the goto that goes outside of the switch-case to a break statement.

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
    # Util methods
    #

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

    @staticmethod
    def replace_nodes(graph, old_node_0, new_node, old_node_1=None):
        in_edges = list(graph.in_edges(old_node_0, data=True))
        out_edges = list(graph.out_edges(old_node_0, data=True))
        if old_node_1 is not None:
            out_edges += list(graph.out_edges(old_node_1, data=True))

        graph.remove_node(old_node_0)
        if old_node_1 is not None:
            graph.remove_node(old_node_1)
        graph.add_node(new_node)
        for src, _, data in in_edges:
            if src is not old_node_0 and src is not old_node_1:
                graph.add_edge(src, new_node, **data)
        for _, dst, data in out_edges:
            if dst is not old_node_0 and dst is not old_node_1:
                graph.add_edge(new_node, dst, **data)

    @staticmethod
    def replace_node_in_node(parent_node: BaseNode, old_node: BaseNode, new_node: BaseNode):
        if isinstance(parent_node, SequenceNode):
            for i in range(len(parent_node.nodes)):
                if parent_node.nodes[i] is old_node:
                    parent_node.nodes[i] = new_node
                    return
        elif isinstance(parent_node, ConditionNode):
            if parent_node.true_node is old_node:
                parent_node.true_node = new_node
                return
            elif parent_node.false_node is old_node:
                parent_node.false_node = new_node
                return
        elif isinstance(parent_node, CascadingConditionNode):
            for i in range(len(parent_node.condition_and_nodes)):
                if parent_node.condition_and_nodes[i][1] is old_node:
                    parent_node.condition_and_nodes[i] = (parent_node.condition_and_nodes[i][0], new_node)
                    return
        else:
            raise TypeError(f"Unsupported node type {type(parent_node)}")

    @staticmethod
    def is_a_jump_target(stmt: Union[ailment.Stmt.ConditionalJump,ailment.Stmt.Jump], addr: int) -> bool:
        if isinstance(stmt, ailment.Stmt.ConditionalJump):
            if isinstance(stmt.true_target, ailment.Expr.Const) and stmt.true_target.value == addr:
                return True
            if isinstance(stmt.false_target, ailment.Expr.Const) and stmt.false_target.value == addr:
                return True
        elif isinstance(stmt, ailment.Stmt.Jump):
            if isinstance(stmt.target, ailment.Expr.Const) and stmt.target.value == addr:
                return True
        return False
