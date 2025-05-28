# pylint:disable=arguments-renamed,too-many-boolean-expressions
from __future__ import annotations
from typing import Any

import angr.ailment as ailment
from angr.ailment.expression import Op

from angr.analyses.decompiler.structuring.structurer_nodes import ConditionNode
from angr.analyses.decompiler.utils import (
    structured_node_is_simple_return,
    structured_node_is_simple_return_strict,
    sequence_to_statements,
    structured_node_has_multi_predecessors,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage


class FlipBooleanWalker(SequenceWalker):
    """
    Walks a SequenceNode and handles every sequence.
    Uses the flip_size to determine when to flip the condition on large if-statement bodies.
    """

    def __init__(self, graph, flip_size=9, last_node=None):
        super().__init__()
        self._graph = graph
        self._last_node = last_node
        self._flip_size = flip_size

    def _handle_Sequence(self, seq_node, **kwargs):
        # Type 1:
        # if (cond) { ... }  else  { return; }   -->   if (!cond) { return; } else { ... }
        #
        # Type 2:
        # if (cond) { ... } return;    -->    if (!cond) return; ...; return;
        type1_condition_nodes = [node for node in seq_node.nodes if isinstance(node, ConditionNode) and node.false_node]
        type2_condition_nodes: list[tuple[int, ConditionNode, Any]] = []

        if len(seq_node.nodes) >= 2:
            idx = len(seq_node.nodes) - 2
            node = seq_node.nodes[idx]
            if (
                isinstance(node, ConditionNode)
                and node.true_node is not None
                and node.false_node is None
                and idx < len(seq_node.nodes) - 1
                and structured_node_is_simple_return_strict(seq_node.nodes[idx + 1])
                and node not in type1_condition_nodes
            ):
                # Type 2: Special Filter:
                # consider code that looks like the following:
                # {if (cond) {LABEL: ... } return;}; goto LABEL;
                #
                # if we were to do the normal flip, this happens:
                # {if (!cond) return; LABEL: ...}; goto LABEL;
                #
                # This is incorrect because we've now created an infinite loop in the event that cond is false,
                # which is not what the original code was. The gist here is that you can't ever flip these cases
                # in the presence of more than one incoming edge to `...` region.
                #
                # To eliminate this illegal case, we simply need to find all the condition nodes of the above structure
                # that have multiple incoming edges to the `...` region.
                illegal_flip = structured_node_has_multi_predecessors(node.true_node, self._graph)
                if not illegal_flip:
                    type2_condition_nodes.append((idx, node, seq_node.nodes[idx + 1]))

        for node in type1_condition_nodes:
            if isinstance(node.condition, Op) and structured_node_is_simple_return(node.false_node, self._graph):
                node.condition = ailment.expression.negate(node.condition)
                node.true_node, node.false_node = node.false_node, node.true_node

        for idx, cond_node, successor in type2_condition_nodes:
            # there are two possibilities when you might want to flip the condition and move the return statement:
            # 1. This if-stmt if found somewhere in the middle of the function
            # 2. This if-stmt is pretty large, but still ends in a return outside of the if-stmt
            if (successor is not self._last_node) or (
                len(sequence_to_statements(cond_node.true_node)) >= self._flip_size
            ):
                cond_node.condition = ailment.expression.negate(cond_node.condition)
                seq_node.nodes[idx + 1] = cond_node.true_node
                cond_node.true_node = successor
                seq_node.nodes.insert(idx + 2, successor)

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

    def __init__(self, func, flip_size=9, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get("graph")
        self._flip_size = flip_size
        self.analyze()

    def _check(self):
        return bool(self.seq.nodes), None

    def _analyze(self, cache=None):
        walker = FlipBooleanWalker(self._graph, last_node=self.seq.nodes[-1], flip_size=self._flip_size)
        walker.walk(self.seq)
        self.out_seq = self.seq
