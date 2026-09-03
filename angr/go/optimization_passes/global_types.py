from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.expression import Const
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.sim_variable import SimMemoryVariable


class _ConstCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.values: set[int] = set()

    def _handle_Const(self, expr_idx, expr: Const, stmt_idx, stmt, block):
        if isinstance(expr.value, int):
            self.values.add(expr.value)


class GoGlobalTypes(OptimizationPass):
    """
    Give package-level variables referenced by this function the types the signature sources (DWARF) know for them,
    pinned as manual types so type inference treats them as ground truth.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Pin Go package-level variable types"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        sigs = self.kb.go_signatures
        sigs.load_sources()
        collector = _ConstCollector()
        for block in self._graph.nodes:
            collector.walk(block)
        if not collector.values:
            return
        global_manager = self.kb.dec_variables["global"]
        for addr in collector.values:
            record = sigs.variable_at(addr)
            if record is None:
                continue
            try:
                ty = sigs.type(record.type_str).with_arch(self.project.arch)
            except Exception:  # pylint:disable=broad-exception-caught
                continue
            size = (ty.size or self.project.arch.bits) // self.project.arch.byte_width
            existing = global_manager.get_global_variables(addr)
            if existing:
                var = next(iter(existing))
            else:
                var = SimMemoryVariable(addr, size, ident=global_manager.next_variable_ident("global"))
                global_manager.set_variable("global", addr, var)
            if var.name is None:
                var.name = record.name
            global_manager.set_variable_type(var, ty, mark_manual=True)
