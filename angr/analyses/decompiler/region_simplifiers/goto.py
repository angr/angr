# pylint:disable=unused-argument,arguments-differ
from typing import Set
import logging

import ailment

from ..sequence_walker import SequenceWalker
from ..structuring.structurer_nodes import BreakNode, ContinueNode
from ..structuring.structurer_nodes import SequenceNode, CodeNode, MultiNode, LoopNode, ConditionNode, \
    CascadingConditionNode, SwitchCaseNode
from .node_address_finder import NodeAddressFinder
from ....knowledge_plugins.gotos import Goto


l = logging.getLogger(name=__name__)


class GotoSimplifier(SequenceWalker):
    """
    Remove unnecessary Jump statements.
    This simplifier also has the side effect of detecting Gotos that can't be reduced in the
    structuring and eventual decompilation output. Because of this, when this analysis is run,
    gotos in decompilation will be detected and stored in the kb.gotos. See the
    _handle_irreducible_goto function below.

    TODO:
    Move the recording of Gotos outside this function
    """
    def __init__(self, node, function=None, kb=None):
        handlers = {
            SequenceNode: self._handle_sequencenode,
            CodeNode: self._handle_codenode,
            MultiNode: self._handle_multinode,
            LoopNode: self._handle_loopnode,
            ConditionNode: self._handle_conditionnode,
            CascadingConditionNode: self._handle_cascadingconditionnode,
            SwitchCaseNode: self._handle_switchcasenode,
            ailment.Block: self._handle_block,
        }
        self._function = function
        self._kb = kb

        super().__init__(handlers)
        self._node_addrs: Set[int] = NodeAddressFinder(node).addrs

        self.walk(node)

    def _handle_sequencenode(self, node, successor=None, **kwargs):
        """

        :param SequenceNode node:
        :return:
        """

        to_replace = []

        for idx, (n0, n1) in enumerate(list(zip(node.nodes, node.nodes[1:] + [successor]))):
            result = self._handle(n0, successor=n1, **kwargs)
            if isinstance(result, list):
                to_replace.append((idx, result))

        for idx, blocks in to_replace:
            node.nodes = node.nodes[:idx] + blocks + node.nodes[idx + 1:]

    def _handle_codenode(self, node, successor=None, **kwargs):
        """

        :param CodeNode node:
        :return:
        """

        result = self._handle(node.node, successor=successor)
        if isinstance(result, list):
            node.node = SequenceNode(node.addr, result)

    def _handle_conditionnode(self, node, successor=None, **kwargs):
        """

        :param ConditionNode node:
        :param successor:
        :return:
        """

        if node.true_node is not None:
            result = self._handle(node.true_node, successor=successor, **kwargs)
            if isinstance(result, list):
                node.true_node = SequenceNode(node.true_node.addr, result)
        if node.false_node is not None:
            result = self._handle(node.false_node, successor=successor, **kwargs)
            if isinstance(result, list):
                node.false_node = SequenceNode(node.false_node.addr, result)

    def _handle_cascadingconditionnode(self, node: CascadingConditionNode, successor=None, **kwargs):

        for idx, (cond, child_node) in enumerate(node.condition_and_nodes):
            result = self._handle(child_node, successor=successor, **kwargs)
            if isinstance(result, list):
                node.condition_and_nodes[idx] = cond, SequenceNode(child_node.addr, result)

        if node.else_node is not None:
            result = self._handle(node.else_node, successor=successor, **kwargs)
            if isinstance(result, list):
                node.else_node = SequenceNode(node.else_node.addr, result)

    def _handle_loopnode(self, node, successor=None, **kwargs):
        """

        :param LoopNode node:
        :param successor:
        :return:
        """

        if 'loop_successor' in kwargs:
            del kwargs['loop_successor']
        if 'loop_head' in kwargs:
            del kwargs['loop_head']

        result = self._handle(node.sequence_node, loop_head=node, loop_successor=successor, **kwargs)
        assert result is None

    def _handle_switchcasenode(self, node: SwitchCaseNode, successor=None, **kwargs):

        if 'loop_successor' in kwargs:
            del kwargs['loop_successor']
        if 'loop_head' in kwargs:
            del kwargs['loop_head']

        for idx, case_node in enumerate(node.cases):
            result = self._handle(case_node, successor=None, **kwargs)
            if isinstance(result, list):
                node.cases[idx] = SequenceNode(node.cases[idx].addr, result)

        if node.default_node is not None:
            result = self._handle(node.default_node, successor=None, **kwargs)
            if isinstance(result, list):
                node.default_node = SequenceNode(node.default_node.addr, result)

    def _handle_multinode(self, node, successor=None, **kwargs):
        """

        :param MultiNode node:
        :return:
        """

        to_replace = []
        for idx, (n0, n1) in enumerate(list(zip(node.nodes, node.nodes[1:] + [successor]))):
            if isinstance(n0, ailment.Block):
                result = self._handle(n0, successor=n1, **kwargs)
                if isinstance(result, list):
                    to_replace.append((idx, result))
            else:
                self._handle(n0, successor=n1, **kwargs)

        for idx, blocks in to_replace:
            node.nodes = node.nodes[:idx] + blocks + node.nodes[idx + 1:]

    def _handle_block(self, block, successor=None, loop_successor=None, loop_head=None, **kwargs):  # pylint:disable=no-self-use
        """
        This will also record irreducible gotos into the kb if found.

        :param ailment.Block block:
        :return:
        """

        if block.statements and isinstance(block.statements[-1], ailment.Stmt.Jump):
            goto_stmt = block.statements[-1]  # ailment.Stmt.Jump
            if isinstance(goto_stmt.target, ailment.Expr.Const):
                goto_target = goto_stmt.target.value
                as_break = False
                as_continue = False
                if successor and goto_target == successor.addr:
                    can_remove = True
                elif goto_target not in self._node_addrs:
                    # the target block has been removed and is no longer exist. we assume this goto is useless
                    can_remove = True
                elif loop_successor is not None and goto_target == loop_successor.addr:
                    # replace it with a break statement
                    can_remove = True
                    as_break = True
                elif loop_head is not None and goto_target == loop_head.addr:
                    # replace it with a continue statement
                    can_remove = True
                    as_continue = True
                else:
                    can_remove = False
                    self._handle_irreducible_goto(block, goto_stmt)

                if can_remove:
                    # we can remove this statement
                    block.statements = block.statements[:-1]
                if as_break:
                    return [block, BreakNode(goto_stmt.ins_addr, loop_successor.addr)]
                if as_continue:
                    return [block, ContinueNode(goto_stmt.ins_addr, loop_head.addr)]
        return None

    def _handle_irreducible_goto(self, block, goto_stmt: ailment.Stmt.Jump):
        if not self._kb or not self._function:
            l.debug("Unable to store a goto at %#x because simplifier is kb or functionless", block.addr)
            return

        goto = Goto(addr=goto_stmt.ins_addr or block.addr, target_addr=goto_stmt.target.value)
        l.debug("Storing %r in kb.gotos", goto)
        self._kb.gotos.locations[self._function.addr].add(
            goto
        )
