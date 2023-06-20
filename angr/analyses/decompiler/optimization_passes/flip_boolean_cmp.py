from typing import List

from ailment.expression import BinaryOp

from ..structuring.structurer_nodes import ConditionNode
from ..structured_codegen.c import is_simple_return_node
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage


class FlipBooleanCmp(SequenceOptimizationPass):
    """
    In the scenario in which a false node has no apparent successors, flip and allow c structured code gen to remove
    redundant else scope.
    """

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["linux", "windows", "cgc"]
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "flip boolean comparison"
    DESCRIPTION = "when false node has no successors, flip condition so else scope can be simplified"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get("graph", None)
        self.analyze()

    def _check(self):
        condition_nodes = [node for node in self.seq.nodes if isinstance(node, ConditionNode) and node.false_node]
        return len(condition_nodes) > 0, condition_nodes

    def _analyze(self, cache=None):
        condition_nodes: List[ConditionNode] = cache or []
        for node in condition_nodes:
            if is_simple_return_node(node.false_node, self._graph):
                node.condition.op = BinaryOp.COMPARISON_NEGATION[node.condition.op]
                node.true_node, node.false_node = node.false_node, node.true_node
