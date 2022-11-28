from typing import Optional, Dict, Set, List, Any, Union, TYPE_CHECKING
from collections import defaultdict
import logging

import networkx

import ailment
import claripy

from ... import Analysis
from ..condition_processor import ConditionProcessor
from ..sequence_walker import SequenceWalker
from ..utils import extract_jump_targets, insert_node
from .structurer_nodes import MultiNode, SequenceNode, SwitchCaseNode, CodeNode, ConditionNode, ConditionalBreakNode, \
    ContinueNode, BaseNode, CascadingConditionNode, BreakNode, LoopNode

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.analyses.decompiler.graph_region import GraphRegion

_l = logging.getLogger(__name__)


class StructurerBase(Analysis):
    """
    The base class for analysis passes that structures a region.

    The current function graph is provided so that we can detect certain edge cases, for example, jump table entries no
    longer exist due to empty node removal during structuring or prior steps.
    """
    def __init__(self, region, parent_map=None, condition_processor=None, func: Optional['Function']=None,
                 case_entry_to_switch_head: Optional[Dict[int,int]]=None, parent_region=None):
        self._region: 'GraphRegion' = region
        self._parent_map = parent_map
        self.function = func
        self._case_entry_to_switch_head = case_entry_to_switch_head
        self._parent_region = parent_region

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
                        insert_node(parent, "after", break_node, index)
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
                    if isinstance(parent, SwitchCaseNode):
                        # the parent of the current node is not a container. insert_node() handles it for us.
                        insert_node(parent, "before", break_node, index, label=label)
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
                    insert_node(parent, "after", new_node, index)
                # remove the current node
                node.statements = [ ]

        def _dummy(node, parent=None, index=None, label=None, **kwargs):  # pylint:disable=unused-argument
            return

        handlers = {
            ailment.Block: _rewrite_conditional_jump_to_break,
            LoopNode: _dummy,
            SwitchCaseNode: _dummy,
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
                    insert_node(parent, "after", continue_node, index, label=label)  # insert after
                    # remove this statement
                    node.statements = node.statements[:-1]

        def _dummy(node, parent=None, index=None, label=None, **kwargs):  # pylint:disable=unused-argument
            return

        handlers = {
            ailment.Block: _rewrite_jump_to_continue,
            LoopNode: _dummy,
        }

        walker = SequenceWalker(handlers=handlers)
        walker.walk(loop_seq)

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
                _l.warning("None of the branches is jumping to outside of the loop")
                raise Exception()

        return new_node

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
    def replace_nodes(graph, old_node_0, new_node, old_node_1=None, self_loop=True):
        in_edges = list(graph.in_edges(old_node_0, data=True))
        out_edges = list(graph.out_edges(old_node_0, data=True))
        if old_node_1 is not None:
            out_edges += list(graph.out_edges(old_node_1, data=True))

        graph.remove_node(old_node_0)
        if old_node_1 is not None:
            graph.remove_node(old_node_1)
        graph.add_node(new_node)
        for src, dst, data in in_edges:
            if src is not old_node_0 and src is not old_node_1:
                graph.add_edge(src, new_node, **data)
            elif src is old_node_1 and dst is old_node_0 and self_loop:
                # self loop
                graph.add_edge(new_node, new_node, **data)
        for src, dst, data in out_edges:
            if dst is not old_node_0 and dst is not old_node_1:
                graph.add_edge(new_node, dst, **data)
            elif src is old_node_1 and dst is old_node_0 and self_loop:
                # self loop
                graph.add_edge(new_node, new_node, **data)

    @staticmethod
    def replace_node_in_node(parent_node: BaseNode, old_node: BaseNode, new_node: BaseNode):
        if isinstance(parent_node, SequenceNode):
            for i in range(len(parent_node.nodes)):  # pylint:disable=consider-using-enumerate
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
            for i in range(len(parent_node.condition_and_nodes)):  # pylint:disable=consider-using-enumerate
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
