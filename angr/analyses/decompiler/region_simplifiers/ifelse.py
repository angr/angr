# pylint:disable=unused-argument,arguments-differ
from __future__ import annotations

from ..sequence_walker import SequenceWalker
from ..structuring.structurer_nodes import (
    SequenceNode,
    CodeNode,
    MultiNode,
    LoopNode,
    ConditionNode,
    EmptyBlockNotice,
    CascadingConditionNode,
)
from ..condition_processor import ConditionProcessor
from ..utils import insert_node, is_statement_terminating


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

    def _handle_Condition(self, node: ConditionNode, parent=None, index=None, **kwargs):
        if node.true_node is not None:
            self._handle(node.true_node, parent=node, index=0)
        if node.false_node is not None:
            self._handle(node.false_node, parent=node, index=1)

        if node.true_node is not None and node.false_node is not None:
            try:
                true_last_stmts = ConditionProcessor.get_last_statements(node.true_node)
            except EmptyBlockNotice:
                true_last_stmts = None
            if (
                true_last_stmts is not None
                and None not in true_last_stmts
                and all(is_statement_terminating(stmt, self.functions) for stmt in true_last_stmts)
            ):
                # all end points in the true node are returning
                try:
                    false_last_stmts = ConditionProcessor.get_last_statements(node.false_node)
                except EmptyBlockNotice:
                    false_last_stmts = None
                if (
                    false_last_stmts is not None
                    and None not in false_last_stmts
                    and not all(is_statement_terminating(stmt, self.functions) for stmt in false_last_stmts)
                ):
                    # not all end points in the false node are returning. in this case, we remove the else node and
                    # make it a new node following node
                    else_node = node.false_node
                    node.false_node = None
                    insert_node(parent, "after", else_node, index, **kwargs)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, parent=None, index=None, **kwargs):
        super()._handle_CascadingCondition(node, parent=parent, index=index, **kwargs)

        if node.else_node is not None:
            last_stmts = []
            for _, subnode in node.condition_and_nodes:
                try:
                    last_stmts.extend(ConditionProcessor.get_last_statements(subnode))
                except EmptyBlockNotice:
                    last_stmts.append(None)

            if (
                last_stmts
                and None not in last_stmts
                and all(is_statement_terminating(stmt, self.functions) for stmt in last_stmts)
            ):
                # all end points in the true node are returning

                # remove the else node and make it a new node following node
                else_node = node.else_node
                node.else_node = None
                insert_node(parent, "after", else_node, index, **kwargs)
