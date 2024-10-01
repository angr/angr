from .base import TransformationPass
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from ...utils.graph import GraphUtils

CLEANUP_FUNCTIONS = ("__rust_dealloc", "close", "core::ptr::drop_in_place")


class CleanupCodeRemover(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove cleanup code"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _get_real_successor(self, blocks_to_replace, block):
        visited = {block}
        while (block := blocks_to_replace[block][1]) not in visited:
            visited.add(block)
            if block not in blocks_to_replace:
                return block
        return None

    def _simplify_if_drop(self):
        blocks_to_replace = {}
        for block in self._graph.nodes:
            if self.match_call(block, CLEANUP_FUNCTIONS):
                predecessors = list(self._graph.predecessors(block))
                successors = list(self._graph.successors(block))
                if len(predecessors) >= 1 and len(successors) == 1:
                    successor = next(iter(successors))
                    blocks_to_replace[block] = (predecessors, successor)
        fixed_blocks_to_replace = {}
        for block, (predecessors, successor) in blocks_to_replace.items():
            new_predecessors = list(filter(lambda pred: pred not in blocks_to_replace, predecessors))
            new_successor = self._get_real_successor(blocks_to_replace, block)
            if len(new_predecessors) and new_successor:
                fixed_blocks_to_replace[block] = (new_predecessors, new_successor)
        for block, (predecessors, successor) in fixed_blocks_to_replace.items():
            for predecessor in predecessors:
                self.replace_jump_target(predecessor, block, successor)
            self._remove_block(block)
        import ipdb

        ipdb.set_trace()

    def _analyze(self, cache=None):
        self._simplify_if_drop()
