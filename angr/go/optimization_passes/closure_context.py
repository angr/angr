from __future__ import annotations

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.runtime_types import CONTEXT_REGISTERS


class GoClosureContextNamer(OptimizationPass):
    """
    Name the variable that stands for the closure context register ``ctx`` and type it as a pointer to the closure
    record its parent built (``*struct { F uintptr; X0 T; ... }``), so captures read as ``ctx.X0``.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Name the Go closure context register"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary and self.project.arch.name in CONTEXT_REGISTERS, None

    def _analyze(self, cache=None):
        sigs = self.kb.go_signatures
        type_str = sigs.closure_context(self._func.addr)
        reg_name = CONTEXT_REGISTERS[self.project.arch.name]
        if type_str is None or reg_name not in self.project.arch.registers:
            return
        if self._func.addr not in self.kb.dec_variables:
            return
        try:
            ctx_type = sigs.type("*" + type_str).with_arch(self.project.arch)
        except Exception:  # pylint:disable=broad-exception-caught
            return
        var_manager = self.kb.dec_variables[self._func.addr]
        for var in var_manager.find_variables_by_register(self.project.arch.registers[reg_name][0]):
            unified = var_manager.unified_variable(var)
            for v in (var, unified):
                if v is not None:
                    v.name = "ctx"
                    v.renamed = True
            var_manager.set_variable_type(var, ctx_type)
