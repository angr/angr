# pylint:disable=unused-argument,arguments-differ
from __future__ import annotations
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


l = logging.getLogger(name=__name__)


class IfSimplifier(SequenceWalker):
    """
    Remove unnecessary jump or conditional jump statements if they jump to the successor right afterwards.
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

        self._handle(node.sequence_node, successor=successor)

    def _handle_multinode(self, node, successor=None, **kwargs):
        """

        :param MultiNode node:
        :return:
        """

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._handle(n0, successor=n1)

    def _handle_block(self, block, successor=None, **kwargs):  # pylint:disable=no-self-use
        """
        Remove unnecessary jump or conditional jump statements if they jump to the successor right afterwards.

        :param ailment.Block block:
        :return:
        """

        if block.statements and isinstance(block.statements[-1], ailment.Stmt.ConditionalJump):
            cond_stmt = block.statements[-1]  # ailment.Stmt.ConditionalJump
            if (
                isinstance(successor, ConditionNode)
                and isinstance(cond_stmt.true_target, ailment.Expr.Const)
                and (
                    (
                        (successor.true_node is not None and cond_stmt.true_target.value == successor.true_node.addr)
                        or (
                            successor.false_node is not None
                            and cond_stmt.true_target.value == successor.false_node.addr
                        )
                    )
                    or (
                        cond_stmt.false_target is not None
                        and (
                            (
                                successor.false_node is not None
                                and cond_stmt.false_target.value == successor.false_node.addr
                            )
                            or (
                                successor.true_node is not None
                                and cond_stmt.false_target.value == successor.true_node.addr
                            )
                        )
                    )
                )
            ):
                # We can safely remove this statement
                block.statements = block.statements[:-1]
