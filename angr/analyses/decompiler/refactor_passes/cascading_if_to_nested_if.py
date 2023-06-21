from .refactor_pass import RefactorPass
from ..structuring.structurer_nodes import CascadingConditionNode, ConditionNode


class CascadingIfToNestedIf(RefactorPass):
    NAME = "Converting a cascading if to a nested if"

    def __init__(self, node: CascadingConditionNode):
        super().__init__()
        self._node = node

        if isinstance(self._node, CascadingConditionNode):
            self._analyze()

    def _analyze(self):
        condition, true_node = self._node.condition_and_nodes[0]
        if len(self._node.condition_and_nodes) == 1:
            false_node = self._node.else_node
        elif len(self._node.condition_and_nodes) == 2:
            # create a new ConditionNode
            false_node_condition, false_node_true_node = self._node.condition_and_nodes[1]
            false_node_false_node = self._node.else_node
            false_node = ConditionNode(
                self._node.addr,
                None,
                false_node_condition,
                false_node_true_node,
                false_node_false_node,
            )
        else:
            # create a new CascadingConditionNode
            false_node = CascadingConditionNode(
                self._node.addr, self._node.condition_and_nodes[1:], self._node.else_node
            )
        new_node = ConditionNode(self._node.addr, None, condition, true_node, false_node)
        self.out_node = new_node
