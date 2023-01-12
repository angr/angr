# pylint:disable=unused-argument,arguments-differ
from typing import Set
import logging

import ailment

from ..sequence_walker import SequenceWalker
from ..structuring.structurer_nodes import (
    SequenceNode,
    CodeNode,
    MultiNode,
    LoopNode,
    ConditionNode,
    CascadingConditionNode,
)
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

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._handle(n0, successor=n1)

    def _handle_codenode(self, node, successor=None, **kwargs):
        """

        :param CodeNode node:
        :return:
        """

        self._handle(node.node, successor=successor)

    def _handle_conditionnode(self, node, successor=None, **kwargs):
        """

        :param ConditionNode node:
        :param successor:
        :return:
        """

        if node.true_node is not None:
            self._handle(node.true_node, successor=successor)
        if node.false_node is not None:
            self._handle(node.false_node, successor=successor)

    def _handle_cascadingconditionnode(self, node: CascadingConditionNode, successor=None, **kwargs):

        for _, child_node in node.condition_and_nodes:
            self._handle(child_node, successor=successor)
        if node.else_node is not None:
            self._handle(node.else_node, successor=successor)

    def _handle_loopnode(self, node, successor=None, **kwargs):
        """

        :param LoopNode node:
        :param successor:
        :return:
        """

        self._handle(
            node.sequence_node,
            successor=node,  # the end of a loop always jumps to the beginning of its body
        )

    def _handle_multinode(self, node, successor=None, **kwargs):
        """

        :param MultiNode node:
        :return:
        """

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._handle(n0, successor=n1)

    def _handle_block(self, block, successor=None, **kwargs):  # pylint:disable=no-self-use
        """
        This will also record irreducible gotos into the kb if found.

        :param ailment.Block block:
        :return:
        """

        if block.statements and isinstance(block.statements[-1], ailment.Stmt.Jump):
            goto_stmt = block.statements[-1]  # ailment.Stmt.Jump
            if isinstance(goto_stmt.target, ailment.Expr.Const):
                goto_target = goto_stmt.target.value
                if successor and goto_target == successor.addr:
                    can_remove = True
                elif goto_target not in self._node_addrs:
                    # the target block has been removed and is no longer exist. we assume this goto is useless
                    can_remove = True
                else:
                    can_remove = False
                    self._handle_irreducible_goto(block, goto_stmt)

                if can_remove:
                    # we can remove this statement
                    block.statements = block.statements[:-1]

    def _handle_irreducible_goto(self, block, goto_stmt: ailment.Stmt.Jump):
        if not self._kb or not self._function:
            l.debug("Unable to store a goto at %#x because simplifier is kb or functionless", block.addr)
            return

        goto = Goto(addr=goto_stmt.ins_addr or block.addr, target_addr=goto_stmt.target.value)
        l.debug("Storing %r in kb.gotos", goto)
        self._kb.gotos.locations[self._function.addr].add(goto)
