from collections import OrderedDict

from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    OptimizationPassStage,
    SequenceOptimizationPass,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import ConditionNode
from angr.rust.structuring.structurer_nodes import PatternMatchNode


class PatternMatchWalker(SequenceWalker):
    def __init__(self):
        super().__init__()

    def _handle_Sequence(self, seq_node, **kwargs):
        nodes = list(seq_node.nodes)
        new_nodes = []
        while len(nodes):
            node = nodes.pop(0)
            next_node = nodes.pop(0) if len(nodes) else None
            if isinstance(node, ConditionNode) and node.true_node is not None and node.false_node is None and next_node:
                true_node = node.true_node
                false_node = next_node
                scrutinee = node.condition.tags.get("scrutinee", None)
                match_arms = node.condition.tags.get("match_arms", None)
                if scrutinee and match_arms:
                    true_variant_and_moves = match_arms[(true_node.addr, true_node.idx)]
                    false_variant_and_moves = match_arms[(false_node.addr, false_node.idx)]
                    if true_variant_and_moves and false_variant_and_moves:
                        arms = OrderedDict([(true_variant_and_moves, true_node), (false_variant_and_moves, false_node)])
                        new_node = PatternMatchNode(scrutinee, arms, None, node.addr)
                        new_nodes.append(new_node)
                        continue
            new_nodes.append(node)
            if next_node:
                nodes.insert(0, next_node)
        seq_node.nodes = new_nodes
        return super()._handle_Sequence(seq_node, **kwargs)


class PatternMatchSimplifier(SequenceOptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Recover idiomatic Rust error handling code"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get("graph")
        self.analyze()

    def _check(self):
        return bool(self.seq.nodes), None

    def _analyze(self, cache=None):
        walker = PatternMatchWalker()
        walker.walk(self.seq)
        self.out_seq = self.seq
