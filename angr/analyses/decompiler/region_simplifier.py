# pylint:disable=unused-argument,arguments-differ
import logging
from typing import Dict, List, Set
from collections import defaultdict

import ailment

from ..analysis import Analysis
from .sequence_walker import SequenceWalker
from .structurer_nodes import SequenceNode, CodeNode, MultiNode, LoopNode, ConditionNode, EmptyBlockNotice, \
    ContinueNode, CascadingConditionNode
from .condition_processor import ConditionProcessor
from .utils import insert_node

l = logging.getLogger(name=__name__)


class NodeAddressFinder(SequenceWalker):
    """
    Walk the entire node and collect all addresses of nodes.
    """
    def __init__(self, node):
        handlers = {
            ailment.Block: self._handle_Block,
        }
        super().__init__(handlers=handlers)
        self.addrs: Set[int] = set()

        self.walk(node)

    def _handle_Block(self, node: ailment.Block, **kwargs):
        self.addrs.add(node.addr)


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


class LoopSimplifier(SequenceWalker):
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
        self.continue_preludes: Dict[LoopNode, List[ailment.Block]] = defaultdict(list)
        self.walk(node)

    def _handle_sequencenode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        for n0, n1, n2 in zip(node.nodes, node.nodes[1:] + [successor], [predecessor] + node.nodes[:-1]):
            self._handle(n0, predecessor=n2, successor=n1, loop=loop, loop_successor=loop_successor)

    def _handle_codenode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        self._handle(node.node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor)

    def _handle_conditionnode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        if node.true_node is not None:
            self._handle(node.true_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor)
        if node.false_node is not None:
            self._handle(node.false_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor)

    def _handle_cascadingconditionnode(self, node: CascadingConditionNode, predecessor=None, successor=None, loop=None,
                                       loop_successor=None, **kwargs):

        for _, child_node in node.condition_and_nodes:
            self._handle(child_node, predecessor=predecessor, successor=successor, loop=loop,
                         loop_successor=loop_successor)
        if node.else_node is not None:
            self._handle(node.else_node, predecessor=predecessor, successor=successor, loop=loop,
                         loop_successor=loop_successor)

    def _handle_loopnode(self, node: LoopNode, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        self._handle(node.sequence_node, predecessor=predecessor, successor=successor, loop=node, loop_successor=successor)

        # find for-loop iterators
        if node.sort == 'while' and self.continue_preludes[node] and \
                (node.condition is not None or len(self.continue_preludes[node]) > 1):
            if all(block.statements for block in self.continue_preludes[node]) and \
                    all(block.statements[-1] == self.continue_preludes[node][0].statements[-1] for block in self.continue_preludes[node]):
                node.sort = 'for'
                node.iterator = self.continue_preludes[node][0].statements[-1]
                for block in self.continue_preludes[node]:
                    block.statements = block.statements[:-1]

        # find for-loop initializers
        if isinstance(predecessor, MultiNode):
            predecessor = predecessor.nodes[-1]
        if node.sort == 'for' and isinstance(predecessor, ailment.Block) and predecessor.statements and \
                isinstance(predecessor.statements[-1], (ailment.Stmt.Assignment, ailment.Stmt.Store)):
            node.initializer = predecessor.statements[-1]
            predecessor.statements = predecessor.statements[:-1]

    def _handle_multinode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        for n0, n1, n2 in zip(node.nodes, node.nodes[1:] + [successor], [predecessor] + node.nodes[:-1]):
            self._handle(n0, predecessor=n2, successor=n1, loop=loop, loop_successor=loop_successor)

    def _handle_block(self, block, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):  # pylint:disable=no-self-use
        if isinstance(successor, ContinueNode) or successor is loop_successor:
            self.continue_preludes[loop].append(block)


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
            self._handle(node.else_node,successor=successor)

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
                    if isinstance(cond_stmt.true_target, ailment.Expr.Const) \
                            and cond_stmt.true_target.value == successor.true_node.addr:
                        true_cond = True
                if cond_stmt.true_target is not None and successor.false_node is not None:
                    # True branch exists. Test if the true target is the address
                    if isinstance(cond_stmt.true_target, ailment.Expr.Const) \
                            and cond_stmt.true_target.value == successor.false_node.addr:
                        true_cond = True

                false_cond = False
                if cond_stmt.false_target is not None and successor.false_node is not None:
                    # False branch exists. Test if the false target is the address
                    if isinstance(cond_stmt.true_target, ailment.Expr.Const) \
                            and cond_stmt.false_target.value == successor.false_node.addr:
                        false_cond = True
                if cond_stmt.false_target is not None and successor.true_node is not None:
                    # True branch exists. Test if the true target is the address
                    if isinstance(cond_stmt.true_target, ailment.Expr.Const) \
                            and cond_stmt.false_target.value == successor.true_node.addr:
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
            CascadingConditionNode: self._handle_CascadingCondition,
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


class CascadingIfsRemover(SequenceWalker):
    """
    Coalesce cascading If constructs. Transforming the following construct::

        if (cond_a) {
            if (cond_b) {
                true_body
            } else { }
        } else { }

    into::

        if (cond_a and cond_b) {
            true_body
        } else { }
    """
    def __init__(self, node):
        handlers = {
            SequenceNode: self._handle_Sequence,
            CodeNode: self._handle_Code,
            MultiNode: self._handle_MultiNode,
            LoopNode: self._handle_Loop,
            ConditionNode: self._handle_Condition,
            CascadingConditionNode: self._handle_CascadingCondition,
        }

        super().__init__(handlers)
        self.walk(node)

    def _handle_Condition(self, node, parent=None, index=None, **kwargs):
        """

        :param ConditionNode node:
        :param successor:
        :return:
        """

        if node.true_node is not None:
            self._handle(node.true_node, parent=node, index=0)
        if node.false_node is not None:
            self._handle(node.false_node, parent=node, index=1)

        if node.true_node is not None and node.false_node is None:
            if isinstance(node.true_node, SequenceNode):
                last_node = None
                if len(node.true_node.nodes) > 1 and all(self.is_empty_node(node_) for node_ in node.true_node.nodes[:-1]):
                    last_node = node.true_node.nodes[-1]
                elif len(node.true_node.nodes) == 1:
                    last_node = node.true_node.nodes[0]

                true_node = last_node

                if isinstance(true_node, ConditionNode) and true_node.true_node is not None and true_node.false_node is None:
                    node.condition = ailment.BinaryOp(None, "LogicalAnd", (node.condition, true_node.condition), False,
                                                      **node.condition.tags)
                    node.true_node = true_node.true_node

    @staticmethod
    def is_empty_node(node):
        if isinstance(node, ailment.Block):
            return not node.statements
        if isinstance(node, SequenceNode):
            return all(CascadingIfsRemover.is_empty_node(n) for n in node.nodes)
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
        #
        r = self._simplify_cascading_ifs(r)
        #
        r = self._simplify_loops(r)

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

    @staticmethod
    def _simplify_cascading_ifs(region):
        CascadingIfsRemover(region)
        return region

    @staticmethod
    def _simplify_loops(region):
        LoopSimplifier(region)
        return region


from ...analyses import AnalysesHub
AnalysesHub.register_default('RegionSimplifier', RegionSimplifier)
