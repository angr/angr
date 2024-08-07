from ailment.statement import ConditionalJump

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from angr.rust.optimization_passes.base import TransformationPass

NON_RETURNING_FUNCTIONS = (
    "alloc::raw_vec::handle_error",
    "alloc::alloc::handle_alloc_error",
    "core::panicking::panic_bounds_check",
)


class ErrorHandlingSimplifier(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify error handling operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _simplify_non_returning_calls(self):
        removed = set()
        for block in self._graph.nodes:
            if (
                block.statements
                and isinstance(block.statements[-1], ConditionalJump)
                and self.num_successors(block) == 2
            ):
                block0, block1 = self.get_two_successors(block)
                if self.match_call(block0, NON_RETURNING_FUNCTIONS):
                    self.replace_jump_target(block, block0, block1)
                    removed.add(block0)
                elif self.match_call(block1, NON_RETURNING_FUNCTIONS):
                    self.replace_jump_target(block, block1, block0)
                    removed.add(block1)
        for block in removed:
            self._graph.remove_node(block)

    def _analyze(self, cache=None):
        self._simplify_non_returning_calls()
