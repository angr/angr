from __future__ import annotations
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass


class RustCallingConvention(OptimizationPass):
    """Apply Rust calling convention analysis results to function prototypes."""

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Recover Rust prototypes and calling convention for current function"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        rcc = self.project.analyses.RustCallingConvention(self._func)
        self._func.prototype = rcc.prototype
        self._func.calling_convention = rcc.calling_convention
        self._func.is_prototype_guessed = False
