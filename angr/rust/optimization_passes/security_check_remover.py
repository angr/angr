from ..mixins.cfg_transformation_mixin import CFGTransformationMixin
from ..mixins.cfa_mixin import CFAMixin
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage

SECURITY_CHECK_FUNCTIONS = (
    "core::panicking::panic_bounds_check",
    "core::str::slice_error_fail",
    "core::panicking::panic_const::panic_const_div_by_zero",
    "core::panicking::panic_const::panic_const_rem_by_zero",
    "core::slice::index::slice_start_index_len_fail",
    "core::slice::index::slice_end_index_len_fail",
    "core::slice::index::slice_index_order_fail",
)


class SecurityCheckRemover(OptimizationPass, CFAMixin, CFGTransformationMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove security check"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        CFGTransformationMixin.__init__(self, self._graph)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes):
            if self.match_call(block, SECURITY_CHECK_FUNCTIONS):
                self.remove_block(block)
