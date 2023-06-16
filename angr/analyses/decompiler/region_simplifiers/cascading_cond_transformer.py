# pylint:disable=no-self-use,arguments-renamed,isinstance-second-argument-not-valid-type
from typing import Optional

import ailment
import claripy

from ..structuring.structurer_nodes import ConditionNode, CascadingConditionNode
from ..sequence_walker import SequenceWalker


class CascadingConditionTransformer(SequenceWalker):
    """
    Identifies and transforms `if { ... } else { if { ... } else { ... } }` to
    `if { ... } else if { ... } else if { ... }`.
    """

    def __init__(self, node):
        handlers = {
            ConditionNode: self._handle_Condition,
        }
        super().__init__(handlers)
        self.cascading_if_node: Optional[CascadingConditionNode] = None

        self.walk(node)

    def _handle_Condition(self, cond_node: ConditionNode, **kwargs):
        if (
            cond_node.false_node is not None
            and isinstance(cond_node.false_node, (ConditionNode, CascadingConditionNode))
            and not isinstance(cond_node.true_node, (ConditionNode, CascadingConditionNode))
            and cond_node.true_node is not None
        ):
            cond_0 = cond_node.condition
            node_0 = cond_node.true_node
            remaining_node = cond_node.false_node

        elif (
            cond_node.true_node is not None
            and isinstance(cond_node.true_node, (ConditionNode, CascadingConditionNode))
            and not isinstance(cond_node.false_node, (ConditionNode, CascadingConditionNode))
            and cond_node.false_node is not None
        ):
            if isinstance(cond_node.condition, claripy.ast.Base):
                cond_0 = claripy.Not(cond_node.condition)
            else:
                cond_0 = ailment.expression.negate(cond_node.condition)
            node_0 = cond_node.false_node
            remaining_node = cond_node.true_node

        else:
            return super()._handle_Condition(cond_node, **kwargs)

        # structure else_node
        if not isinstance(remaining_node, CascadingConditionNode):
            structured = self._handle_Condition(remaining_node)
            if structured is None:
                structured = remaining_node
        else:
            structured = remaining_node

        if isinstance(structured, ConditionNode):
            if structured.true_node is None and structured.false_node is not None:
                if isinstance(structured.condition, claripy.ast.Base):
                    negated_structured_condition = claripy.Not(structured.condition)
                else:
                    negated_structured_condition = ailment.expression.negate(structured.condition)
                cond_and_nodes = [
                    (cond_0, node_0),
                    (negated_structured_condition, structured.false_node),
                ]
                else_node = None
            elif structured.true_node is not None and structured.false_node is None:
                cond_and_nodes = [
                    (cond_0, node_0),
                    (structured.condition, structured.true_node),
                ]
                else_node = None
            else:
                cond_and_nodes = [
                    (cond_0, node_0),
                    (structured.condition, structured.true_node),
                ]
                else_node = structured.false_node

        elif isinstance(structured, CascadingConditionNode):
            # merge two nodes
            cond_and_nodes = [(cond_0, node_0)] + structured.condition_and_nodes
            else_node = structured.else_node

        else:
            # unexpected!
            raise RuntimeError("Impossible happened")

        return CascadingConditionNode(cond_node.addr, cond_and_nodes, else_node=else_node)
