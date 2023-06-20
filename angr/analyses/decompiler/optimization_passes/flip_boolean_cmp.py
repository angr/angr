from typing import List

from ailment.expression import BinaryOp
from ailment.block import Block

from ..structuring.structurer_nodes import ConditionNode, SequenceNode
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage

class FlipBooleanCmp(SequenceOptimizationPass):
    ARCHES = ['X86', 'AMD64']
    PLATFORMS = ['linux', 'windows', 'cgc']
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "flip boolean comparison"
    DESCRIPTION = "there is no salvation for the wicked, free will is an illusion"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get('graph', None)
        self.analyze()

    def _check(self):
        condition_nodes = [
            node for node in self.seq.nodes
            if isinstance(node, ConditionNode)
            and node.false_node
        ] 
        return len(condition_nodes) > 0, condition_nodes

    def _analyze(self, cache=None):
        condition_nodes: List[ConditionNode] = cache or []
        last_block=None
        for node in condition_nodes:
            if isinstance(node.false_node, SequenceNode):
                for node in node.false_node.nodes:
                    if not isinstance(node, Block):
                        break
                else:
                    last_block = node
            elif isinstance(node.false_node, Block):
                last_block = node.false_node

            if last_block and not [*self._graph.successors(last_block)]:
                node.condition.op = BinaryOp.COMPARISON_NEGATION[node.condition.op]
                node.true_node, node.false_node = node.false_node, node.true_node

