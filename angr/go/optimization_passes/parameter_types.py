from __future__ import annotations

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.sim_type import GoSimTypeFunction


class GoParameterTypes(OptimizationPass):
    """
    Pin the types of parameter variables to the function's Go prototype so type inference treats them as ground
    truth instead of re-deriving (and often flattening) string/slice/struct parameters from their uses.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Pin Go parameter types"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary and isinstance(self._func.prototype, GoSimTypeFunction), None

    def _analyze(self, cache=None):
        if not self._arg_vvars:
            return
        proto = self._func.prototype
        assert isinstance(proto, GoSimTypeFunction)
        var_manager = self.kb.dec_variables[self._func.addr]
        params = [var for _, var in self._arg_vvars.values()]
        if len(params) != len(proto.args):
            return
        for var, ty in zip(params, proto.args):
            if var is None or ty is None:
                continue
            var_manager.set_variable_type(var, ty.with_arch(self.project.arch), mark_manual=True)
