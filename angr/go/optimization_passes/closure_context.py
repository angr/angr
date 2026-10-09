from __future__ import annotations

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.runtime_types import CONTEXT_REGISTERS
from angr.go.typehoon.hints import closure_context_vvars
from angr.go.utils.names import is_go_closure_name

CLOSURE_CONTEXT_NAME = "ctx"


class GoClosureContextNamer(OptimizationPass):
    """
    Name the variable that stands for the incoming closure context register ``ctx`` (codegen prints it as the first
    parameter) and, when the parent's closure record is known, type it as ``*struct { F uintptr; X0 T; ... }`` so
    captures read as ``ctx.X0``.
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
        if reg_name not in self.project.arch.registers:
            return
        if type_str is None and not is_go_closure_name(self._func.name):
            return
        if self._func.addr not in self.kb.dec_variables:
            return
        ctx_type = None
        if type_str is not None:
            try:
                ctx_type = sigs.type("*" + type_str).with_arch(self.project.arch)
            except Exception:  # pylint:disable=broad-exception-caught
                ctx_type = None
        var_manager = self.kb.dec_variables[self._func.addr]
        # only the value live on entry: later writes to the register are scratch
        for varid in closure_context_vvars(self.project, self._graph):
            var = var_manager.variable_by_vvar_id(varid)
            if var is None:
                continue
            for v in (var, var_manager.unified_variable(var)):
                if v is not None:
                    v.name = CLOSURE_CONTEXT_NAME
                    v.renamed = True
            if ctx_type is not None:
                var_manager.set_variable_type(var, ctx_type)
