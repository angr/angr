from __future__ import annotations

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.runtime_types import G_REGISTERS, go_g_struct
from angr.sim_type import SimTypePointer


class GoPinnedRegisterNamer(OptimizationPass):
    """
    Name the variable that stands for the g register ``g`` and type it ``*runtime.g``.

    The register is never written by compiled Go code, so variable recovery sees an undefined input and names it like
    any other; the name and type make g.m / g.stackguard0 accesses readable.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Name the Go g register"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary and self.project.arch.name in G_REGISTERS, None

    def _analyze(self, cache=None):
        reg_name = G_REGISTERS[self.project.arch.name]
        if reg_name not in self.project.arch.registers:
            return
        reg_offset = self.project.arch.registers[reg_name][0]
        if self._func.addr not in self.kb.dec_variables:
            return
        var_manager = self.kb.dec_variables[self._func.addr]

        g_type = SimTypePointer(go_g_struct(self.project.arch)).with_arch(self.project.arch)
        for var in var_manager.find_variables_by_register(reg_offset):
            unified = var_manager.unified_variable(var)
            for v in (var, unified):
                if v is not None:
                    v.name = "g"
                    v.renamed = True  # keep semantic naming from replacing it
            var_manager.set_variable_type(var, g_type)
