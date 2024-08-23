# pylint:disable=unused-argument,arguments-differ
from __future__ import annotations
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
from ..utils import is_empty_node


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
                if len(node.true_node.nodes) > 1 and all(is_empty_node(node_) for node_ in node.true_node.nodes[:-1]):
                    last_node = node.true_node.nodes[-1]
                elif len(node.true_node.nodes) == 1:
                    last_node = node.true_node.nodes[0]

                true_node = last_node
            elif isinstance(node.true_node, ConditionNode):
                true_node = node.true_node
            else:
                return

            if (
                isinstance(true_node, ConditionNode)
                and true_node.true_node is not None
                and true_node.false_node is None
            ):
                node.condition = ailment.BinaryOp(
                    None, "LogicalAnd", (node.condition, true_node.condition), False, **node.condition.tags
                )
                node.true_node = true_node.true_node
