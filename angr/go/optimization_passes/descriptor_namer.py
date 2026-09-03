from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.expression import Const
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class _ConstCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.values: set[int] = set()

    def _handle_Const(self, expr_idx, expr: Const, stmt_idx, stmt, block):
        if isinstance(expr.value, int):
            self.values.add(expr.value)


class GoDescriptorNamer(OptimizationPass):
    """
    Name globals that are runtime type descriptors or itabs the way the linker does (``type:int``,
    ``go:itab.*os.File,io.Writer``), so stripped binaries read like unstripped ones.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Name Go type descriptor globals"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        collector = _ConstCollector()
        for block in self._graph.nodes:
            collector.walk(block)
        if not collector.values:
            return
        go_types = self.kb.go_types
        global_manager = self.kb.dec_variables["global"]
        for addr in collector.values:
            name = None
            itab = go_types.itab_at(addr)
            if itab is not None:
                name = f"go:itab.{itab[1]},{itab[0]}"
            else:
                type_name = go_types.name_at(addr)
                if type_name is not None:
                    name = f"type:{type_name}"
            if name is None:
                continue
            for var in global_manager.get_global_variables(addr):
                if var.addr == addr and (var.name is None or var.name.startswith("g_")):
                    var.name = name
                    var.renamed = True
