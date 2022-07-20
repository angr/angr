from ailment.expression import BinaryOp

from .refactor_pass import RefactorPass
from ..structuring.structurer_nodes import ConditionNode


CascadingIfElseCase = -1


class MergeNestedIfs(RefactorPass):
    NAME = "Merge nested condition nodes into one condition node"

    def __init__(self, node: ConditionNode):
        super().__init__()
        self._node = node

        if isinstance(self._node, ConditionNode):
            if self._node.true_node is not None and self._node.false_node is None:
                if isinstance(self._node.true_node, ConditionNode) and self._node.true_node.false_node is None:
                    self._analyze()

    def _analyze(self):
        inner_cond_node = self._node.true_node
        new_condition = BinaryOp(
            None,
            "LogicalAnd",
            [self._node.condition, inner_cond_node.condition],
            False,
            bits=1,
            **self._node.condition.tags,
        )
        new_node = ConditionNode(
            self._node.addr,
            self._node.reaching_condition,
            new_condition,
            inner_cond_node.true_node,
            None,
        )
        self.out_node = new_node
