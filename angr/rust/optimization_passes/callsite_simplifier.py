from ailment import Const
from ailment.statement import Call

from angr.analyses.decompiler.clinic import ClinicMode
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from angr.rust.optimization_passes.base import TransformationPass
from angr.rust.sim_type import RustSimTypeFunction
from angr.rust.utils.ail_util import get_terminal_call


class CallsiteSimplifier(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify function return sites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            call = get_terminal_call(block)
            if (
                call
                and not isinstance(call.prototype, RustSimTypeFunction)
                and isinstance(call.target, Const)
                and call.target.value in self.kb.functions
            ):
                func = self.kb.functions[call.target.value]
                post_callsite_block = self.get_one_successor(block) if self.num_successors(block) == 1 else None
                rcc = self.project.analyses.RustCallingConvention(
                    func, callsite_block=block, post_callsite_block=post_callsite_block
                )
                call.prototype = rcc.model.inferred_prototype
