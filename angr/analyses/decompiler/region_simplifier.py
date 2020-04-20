# pylint:disable=unused-argument,arguments-differ
import logging

import ailment

from ..analysis import Analysis
from .sequence_walker import SequenceWalker
from .structurer_nodes import SequenceNode, CodeNode, MultiNode, LoopNode, ConditionNode, EmptyBlockNotice
from .condition_processor import ConditionProcessor
from .utils import insert_node

l = logging.getLogger(name=__name__)


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

        :param ailment.Block block:
        :return:
        """

        if block.statements and isinstance(block.statements[-1], ailment.Stmt.Jump):
            goto_stmt = block.statements[-1]  # ailment.Stmt.Jump
            if successor and isinstance(goto_stmt.target, ailment.Expr.Const) \
                    and goto_stmt.target.value == successor.addr:
                # we can remove this statement
                block.statements = block.statements[:-1]


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


class IfElseFlattener(SequenceWalker):
    """
    Remove unnecessary else branches and make the else node a direct successor of the previous If node if the If node
    always returns.
    """
    def __init__(self, node, functions):
        handlers = {
            SequenceNode: self._handle_Sequence,
            CodeNode: self._handle_Code,
            MultiNode: self._handle_MultiNode,
            LoopNode: self._handle_Loop,
            ConditionNode: self._handle_Condition,
        }

        super().__init__(handlers)
        self.functions = functions
        self.walk(node)

    def _handle_Condition(self, node, parent=None, index=None, **kwargs):
        """

        :param ConditionNode node:
        :param successor:
        :return:
        """

        if node.true_node is not None and node.false_node is not None:
            try:
                last_stmts = ConditionProcessor.get_last_statements(node.true_node)
            except EmptyBlockNotice:
                last_stmts = None
            if last_stmts is not None and all(self._is_statement_terminating(stmt) for stmt in last_stmts):
                # all end points in the true node are returning

                # remove the else node and make it a new node following node
                else_node = node.false_node
                node.false_node = None
                insert_node(parent, index + 1, else_node, index)

        if node.true_node is not None:
            self._handle(node.true_node, parent=node, index=0)
        if node.false_node is not None:
            self._handle(node.false_node, parent=node, index=1)

    def _is_statement_terminating(self, stmt):

        if isinstance(stmt, ailment.Stmt.Return):
            return True
        if isinstance(stmt, ailment.Stmt.Call) and isinstance(stmt.target, ailment.Expr.Const):
            # is it calling a non-returning function?
            target_func_addr = stmt.target.value
            try:
                func = self.functions.get_by_addr(target_func_addr)
                return func.returning is False
            except KeyError:
                pass
        return False


class RegionSimplifier(Analysis):
    def __init__(self, region):
        self.region = region

        self.result = None

        self._simplify()

    def _simplify(self):
        """
        RegionSimplifier performs the following simplifications:
        - Remove redundant Gotos
        - Remove redundant If/If-else statements
        """

        r = self.region
        # Remove unnecessary Jump statements
        r = self._simplify_gotos(r)
        # Remove unnecessary jump or conditional jump statements if they jump to the successor right afterwards
        r = self._simplify_ifs(r)
        # Remove unnecessary else branches if the if branch will always return
        r = self._simplify_ifelses(r)

        self.result = r

    #
    # Simplifiers
    #

    @staticmethod
    def _simplify_gotos(region):
        GotoSimplifier(region)
        return region

    @staticmethod
    def _simplify_ifs(region):
        IfSimplifier(region)
        return region

    def _simplify_ifelses(self, region):
        IfElseFlattener(region, self.kb.functions)
        return region


from ...analyses import AnalysesHub
AnalysesHub.register_default('RegionSimplifier', RegionSimplifier)
