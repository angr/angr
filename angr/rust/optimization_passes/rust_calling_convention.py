from angr.ailment.expression import VirtualVariable, Const, UnaryOp
from angr.ailment.statement import Assignment
from angr.rust.mixins import CFAMixin, SSAVariableMixin
from angr.rust.analyses.rust_calling_convention import Pathfinder
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.optimization_passes.cleanup_code_remover import CLEANUP_FUNCTIONS
from angr.rust.optimization_passes.utils import CallRewriter
from angr.rust.sim_type import RustSimTypeFunction, is_composite_type


class RustCallingConvention(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Recover Rust prototypes and calling convention for current function"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        rcc = self.project.analyses.RustCallingConvention(self._func)
        self._func.prototype = rcc.prototype
        self._func.calling_convention = rcc.calling_convention
        self._func.is_prototype_guessed = False
