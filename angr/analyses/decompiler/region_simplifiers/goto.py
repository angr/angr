# pylint:disable=unused-argument,arguments-differ
from typing import Set

import ailment

from ..sequence_walker import SequenceWalker
from ..structurer_nodes import SequenceNode, CodeNode, MultiNode, LoopNode, ConditionNode, CascadingConditionNode
from .node_address_finder import NodeAddressFinder


class GotoSimplifier(SequenceWalker):
    """
    Remove unnecessary Jump statements.
    """
    def __init__(self, node):
        handlers = {
            SequenceNode: self._handle_sequencenode,
            CodeNode: self._handle_codenode,
            MultiNode: self._handle_multinode,
            LoopNode: self._handle_loopnode,
            ConditionNode: self._handle_conditionnode,
            CascadingConditionNode: self._handle_cascadingconditionnode,
            ailment.Block: self._handle_block,
        }

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
            self._handle(node.else_node)

    def _handle_loopnode(self, node, successor=None, **kwargs):
        """

        :param LoopNode node:
        :param successor:
        :return:
        """

        self._handle(node.sequence_node,
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

                if can_remove:
                    # we can remove this statement
                    block.statements = block.statements[:-1]
