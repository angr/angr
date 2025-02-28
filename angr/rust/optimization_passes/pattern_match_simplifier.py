from collections import OrderedDict
from typing import Dict, Tuple

from ailment import Statement

from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    OptimizationPassStage,
    SequenceOptimizationPass,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.rust.sim_type import EnumVariant
from angr.rust.structuring.structurer_nodes import PatternMatchNode


class PatternMatchWalker(SequenceWalker):
    def __init__(self):
        super().__init__()

    def _build_pattern_match(self, true_node, false_node, condition, addr):
        scrutinee = condition.tags.get("scrutinee", None)
        match_arms: Dict[int, Tuple[EnumVariant, Tuple[Statement]]] = condition.tags.get("match_arms", None)
        true_variant_and_moves, false_variant_and_moves = None, None
        if match_arms:
            if true_node.addr in match_arms and false_node.addr in match_arms:
                true_variant_and_moves = match_arms[true_node.addr]
                false_variant_and_moves = match_arms[false_node.addr]
            elif true_node.addr in match_arms and false_node.addr not in match_arms:
                true_variant_and_moves = match_arms[true_node.addr]
                false_variant_and_moves = next(iter(v for k, v in match_arms.items() if k != true_node.addr))
            elif false_node.addr in match_arms and true_node.addr not in match_arms:
                false_variant_and_moves = match_arms[false_node.addr]
                true_variant_and_moves = next(iter(v for k, v in match_arms.items() if k != false_node.addr))

        if scrutinee and match_arms and true_variant_and_moves is not None and false_variant_and_moves is not None:
            arms = OrderedDict([(true_variant_and_moves, true_node), (false_variant_and_moves, false_node)])
            scrutinee.tags["call"] = condition.tags.get("call", None)
            result = PatternMatchNode(scrutinee, arms, None, addr)
            for stmt in true_variant_and_moves[1] + false_variant_and_moves[1]:
                if stmt:
                    stmt.tags["hidden"] = True
            return result
        return None

    def _handle_Condition(self, node, **kwargs):
        if node.true_node and node.false_node:
            true_node = node.true_node
            false_node = node.false_node
            pattern_match = self._build_pattern_match(true_node, false_node, node.condition, node.addr)
            if pattern_match:
                new_node = super()._handle_PatternMatch(pattern_match, **kwargs)
                return new_node or pattern_match
        return super()._handle_Condition(node, **kwargs)


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
