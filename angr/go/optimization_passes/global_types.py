from __future__ import annotations

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import Const, Convert, Load
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.sim_variable import SimMemoryVariable


class _ConstCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.values: set[int] = set()

    def _handle_Const(self, expr_idx, expr: Const, stmt_idx, stmt, block):
        if isinstance(expr.value, int):
            self.values.add(expr.value)


class _FlagLoadNarrower(AILBlockRewriter):
    """``cmpl $0, runtime.writeBarrier`` reads the bool ``enabled`` and its padding as one word; read the bool."""

    def __init__(self, manager, addr: int):
        super().__init__()
        self._manager = manager
        self._addr = addr
        self.changed = False

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.addr, Const) and expr.addr.value == self._addr and expr.size > 1:
            self.changed = True
            narrow = Load(self._manager.next_atom(), expr.addr, 1, expr.endness, **expr.tags)
            return Convert(self._manager.next_atom(), 8, expr.bits, False, narrow, **expr.tags)
        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)


class GoGlobalTypes(OptimizationPass):
    """
    Give package-level variables referenced by this function the types the signature sources (DWARF) know for them,
    and the runtime's itabs and type descriptors their struct types, pinned as manual types so type inference treats
    them as ground truth (an itab's Type word read through ``go:itab.*T,I`` is then ``.Type``, not ``field_8``).
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
        go_types = self.kb.go_types
        for addr in collector.values:
            record = sigs.variable_at(addr)
            if record is None:
                runtime_ty = None
                if go_types.itab_at(addr) is not None:
                    runtime_ty = sigs.parser.itab_type()
                elif go_types.name_at(addr) is not None:
                    runtime_ty = sigs.parser.type_descriptor_type()
                if runtime_ty is not None:
                    self._pin_global(global_manager, addr, runtime_ty.with_arch(self.project.arch))
                continue
            if record.name == "runtime.writeBarrier":
                narrower = _FlagLoadNarrower(self.manager, addr)
                for block in self._graph.nodes:
                    narrower.walk(block)
                if narrower.changed:
                    self.out_graph = self._graph
            try:
                ty = sigs.type(record.type_str).with_arch(self.project.arch)
            except Exception:  # pylint:disable=broad-exception-caught
                ty = None
            size = (ty.size or self.project.arch.bits) // self.project.arch.byte_width if ty is not None else None
            existing = [v for v in global_manager.get_global_variables(addr) if v.addr == addr]
            if existing:
                var = existing[0]
            else:
                var = SimMemoryVariable(
                    addr, size or self.project.arch.bytes, ident=global_manager.next_variable_ident("global")
                )
                global_manager.set_variable("global", addr, var)
            if var.name is None or var.name.startswith("g_"):
                var.name = record.name
                var.renamed = True
            if ty is not None:
                global_manager.set_variable_type(var, ty, mark_manual=True)

    def _pin_global(self, global_manager, addr: int, ty) -> None:
        size = (ty.size or self.project.arch.bits) // self.project.arch.byte_width
        existing = [v for v in global_manager.get_global_variables(addr) if v.addr == addr]
        if existing:
            var = existing[0]
        else:
            var = SimMemoryVariable(addr, size, ident=global_manager.next_variable_ident("global"))
            global_manager.set_variable("global", addr, var)
        global_manager.set_variable_type(var, ty, mark_manual=True)
