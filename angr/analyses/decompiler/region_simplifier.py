
import logging

import ailment

from ..analysis import Analysis
from .structurer import SequenceNode, CodeNode, MultiNode, LoopNode, ConditionNode

l = logging.getLogger(name=__name__)


class RegionSimplifier(Analysis):
    def __init__(self, region):
        self.region = region

        self.result = None

        # Initialize handler map
        self.GOTO_HANDLERS = {
            SequenceNode: self._goto_handle_sequencenode,
            CodeNode: self._goto_handle_codenode,
            MultiNode: self._goto_handle_multinode,
            LoopNode: self._goto_handle_loopnode,
            ConditionNode: self._goto_handle_conditionnode,
            ailment.Block: self._goto_handle_block,
        }
        self.IFS_HANDLERS = {
            SequenceNode: self._ifs_handle_sequencenode,
            CodeNode: self._ifs_handle_codenode,
            MultiNode: self._ifs_handle_multinode,
            LoopNode: self._ifs_handle_loopnode,
            ConditionNode: self._ifs_handle_conditionnode,
            ailment.Block: self._ifs_handle_block,
        }

        self._simplify()

    def _simplify(self):
        """
        RegionSimplifier performs the following simplifications:
        - Remove redundant Gotos
        - Remove redundant If/If-else statements
        """

        r = self.region
        r = self._simplify_gotos(r)
        r = self._simplify_ifs(r)

        self.result = r

    #
    # Simplifiers
    #

    # Goto simplifier

    def _simplify_gotos(self, region):

        self._goto_handle(region, None)

        return region

    def _goto_handle(self, node, successor):

        handler = self.GOTO_HANDLERS.get(node.__class__, None)
        if handler is not None:
            handler(node, successor)

    def _goto_handle_sequencenode(self, node, successor):
        """

        :param SequenceNode node:
        :return:
        """

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._goto_handle(n0, n1)

    def _goto_handle_codenode(self, node, successor):
        """

        :param CodeNode node:
        :return:
        """

        self._goto_handle(node.node, successor)

    def _goto_handle_conditionnode(self, node, successor):
        """

        :param ConditionNode node:
        :param successor:
        :return:
        """

        if node.true_node is not None:
            self._goto_handle(node.true_node, successor)
        if node.false_node is not None:
            self._goto_handle(node.false_node, successor)

    def _goto_handle_loopnode(self, node, successor):
        """

        :param LoopNode node:
        :param successor:
        :return:
        """

        self._goto_handle(node.sequence_node, successor)

    def _goto_handle_multinode(self, node, successor):
        """

        :param MultiNode node:
        :return:
        """

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._goto_handle(n0, n1)

    def _goto_handle_block(self, block, successor):  # pylint:disable=no-self-use
        """

        :param ailment.Block block:
        :return:
        """

        if block.statements and isinstance(block.statements[-1], ailment.Stmt.Jump):
            goto_stmt = block.statements[-1]  # ailment.Stmt.Jump
            if successor and isinstance(goto_stmt.target, ailment.Expr.Const) \
                    and goto_stmt.target.value == successor.addr:
                # we can remove this statement
                block.statements = block.statements[:-1]

    # Ifs simplifier

    def _simplify_ifs(self, region):

        self._ifs_handle(region, None)

        return region

    def _ifs_handle(self, node, successor):

        handler = self.IFS_HANDLERS.get(node.__class__, None)
        if handler is not None:
            handler(node, successor)

    def _ifs_handle_sequencenode(self, node, successor):
        """

        :param SequenceNode node:
        :return:
        """

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._ifs_handle(n0, n1)

    def _ifs_handle_codenode(self, node, successor):
        """

        :param CodeNode node:
        :return:
        """

        self._ifs_handle(node.node, successor)

    def _ifs_handle_conditionnode(self, node, successor):
        """

        :param ConditionNode node:
        :param successor:
        :return:
        """

        if node.true_node is not None:
            self._ifs_handle(node.true_node, successor)
        if node.false_node is not None:
            self._ifs_handle(node.false_node, successor)

    def _ifs_handle_loopnode(self, node, successor):
        """

        :param LoopNode node:
        :param successor:
        :return:
        """

        self._ifs_handle(node.sequence_node, successor)

    def _ifs_handle_multinode(self, node, successor):
        """

        :param MultiNode node:
        :return:
        """

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._ifs_handle(n0, n1)

    def _ifs_handle_block(self, block, successor):  # pylint:disable=no-self-use
        """

        :param ailment.Block block:
        :return:
        """

        if block.statements and isinstance(block.statements[-1], ailment.Stmt.ConditionalJump):
            cond_stmt = block.statements[-1]  # ailment.Stmt.ConditionalJump
            if isinstance(successor, ConditionNode):
                true_cond = False
                if cond_stmt.true_target is not None and successor.true_node is not None:
                    # True branch exists. Test if the true target is the address
                    if cond_stmt.true_target.value == successor.true_node.addr:
                        true_cond = True
                if cond_stmt.true_target is not None and successor.false_node is not None:
                    # True branch exists. Test if the true target is the address
                    if cond_stmt.true_target.value == successor.false_node.addr:
                        true_cond = True

                false_cond = False
                if cond_stmt.false_target is not None and successor.false_node is not None:
                    # False branch exists. Test if the false target is the address
                    if cond_stmt.false_target.value == successor.false_node.addr:
                        false_cond = True
                if cond_stmt.false_target is not None and successor.true_node is not None:
                    # True branch exists. Test if the true target is the address
                    if cond_stmt.false_target.value == successor.true_node.addr:
                        false_cond = True

                if true_cond or false_cond:
                    # We can safely remove this statement
                    block.statements = block.statements[:-1]
                else:
                    l.error("An unexpected successor %s follows the conditional statement %s.",
                            successor, cond_stmt
                            )


from ...analyses import AnalysesHub
AnalysesHub.register_default('RegionSimplifier', RegionSimplifier)
