# pylint:disable=unused-argument,arguments-differ
import ailment

from ..sequence_walker import SequenceWalker
from ..structurer_nodes import SequenceNode, CodeNode, MultiNode, LoopNode, ConditionNode, EmptyBlockNotice, \
    CascadingConditionNode
from ..condition_processor import ConditionProcessor
from ..utils import insert_node


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
