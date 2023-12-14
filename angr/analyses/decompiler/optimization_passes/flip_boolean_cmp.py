# pylint:disable=arguments-renamed,too-many-boolean-expressions
from typing import List, Tuple, Any

import ailment
from ailment.expression import Op

from ..structuring.structurer_nodes import ConditionNode
from ..utils import structured_node_is_simple_return
from ..sequence_walker import SequenceWalker
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage


class FlipBooleanWalker(SequenceWalker):
    """
    Walks a SequenceNode and handles every sequence.
    """

    def __init__(self, graph, last_node=None):
        super().__init__()
        self._graph = graph
        self._last_node = last_node

    def _handle_Sequence(self, seq_node, **kwargs):
        # Type 1:
        # if (cond) { ... }  else  { return; }   -->   if (!cond) { return; } else { ... }
        #
        # Type 2:
        # if (cond) { ... } return;    -->    if (!cond) return; ...
        type1_condition_nodes = [node for node in seq_node.nodes if isinstance(node, ConditionNode) and node.false_node]
        type2_condition_nodes: List[Tuple[int, ConditionNode, Any]] = []

        if len(seq_node.nodes) >= 2:
            idx = len(seq_node.nodes) - 2
            node = seq_node.nodes[idx]
            if (
                isinstance(node, ConditionNode)
                and node.true_node is not None
                and node.false_node is None
                and idx < len(seq_node.nodes) - 1
                and structured_node_is_simple_return(seq_node.nodes[idx + 1], self._graph)
                and node not in type1_condition_nodes
            ):
                type2_condition_nodes.append((idx, node, seq_node.nodes[idx + 1]))

        for node in type1_condition_nodes:
            if isinstance(node.condition, Op) and structured_node_is_simple_return(node.false_node, self._graph):
                node.condition = ailment.expression.negate(node.condition)
                node.true_node, node.false_node = node.false_node, node.true_node

        for idx, cond_node, successor in type2_condition_nodes:
            # flipping the condition on the last node of the program will cause
            # the program to look strange, so avoid this case
            if successor is not self._last_node:
                cond_node.condition = ailment.expression.negate(cond_node.condition)
                seq_node.nodes[idx + 1] = cond_node.true_node
                cond_node.true_node = successor

        return super()._handle_Sequence(seq_node, **kwargs)


class FlipBooleanCmp(SequenceOptimizationPass):
    """
    In the scenario in which a false node has no apparent successors, flip the condition on that if-stmt.
    This is only useful when StructuredCodeGenerator has simplify_else_scopes enabled, as this will allow the
    flipped if-stmt to remove the redundant else.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Flip small ret booleans"
    DESCRIPTION = "When false node has no successors, flip condition so else scope can be simplified later"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get("graph", None)
        self.analyze()

    def _check(self):
        return bool(self.seq.nodes), None

    def _analyze(self, cache=None):
        walker = FlipBooleanWalker(self._graph, last_node=self.seq.nodes[-1])
        walker.walk(self.seq)
        self.out_seq = self.seq
