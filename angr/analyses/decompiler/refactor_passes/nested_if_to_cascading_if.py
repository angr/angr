from ..region_simplifiers.cascading_cond_transformer import CascadingConditionTransformer
from ..structuring.structurer_nodes import ConditionNode
from .refactor_pass import RefactorPass


class NestedIfToCascadingIf(RefactorPass):
    NAME = "Converting a nested if to a cascading if"

    def __init__(self, node: ConditionNode):
        super().__init__()
        self._node = node

        self._analyze()

    def _analyze(self):
        transformer = CascadingConditionTransformer(self._node, walk=False)
        new_node = transformer._handle_Condition(self._node)
        self.out_node = new_node
