from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from angr.rust.optimization_passes.base import TransformationPass

DECONSTRUCTION_FUNCTIONS = ("__rust_dealloc", "close", "core::ptr::drop_in_place")


class LifetimeSimplifier(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify lifetime ending operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            if self.match_call(block, DECONSTRUCTION_FUNCTIONS):
                self.replace_call_with_jump(block)
