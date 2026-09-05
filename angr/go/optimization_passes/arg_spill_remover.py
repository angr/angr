from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.expression import Const, VirtualVariable
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class _VVarUseCollector(AILBlockViewer):
    """Collect the ids of every virtual variable that is read (assignment destinations are not reads)."""

    def __init__(self):
        super().__init__()
        self.used: set[int] = set()

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block):
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt, block):
        self.used.add(expr.varid)


class GoArgSpillRemover(OptimizationPass):
    """
    Drop stores into the incoming-argument spill area that the function never reads back.

    Under Go's register ABI the caller reserves a spill slot per register argument in its own frame, and the callee
    spills into those slots whenever it needs them (the morestack path, or every argument in unoptimized code). The
    slots sit above the return address, so the generic dead-store removal treats them as caller memory and keeps the
    stores. Nothing but this function ever reads them.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Remove unread Go argument spills"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        collector = _VVarUseCollector()
        for block in self._graph.nodes:
            collector.walk(block)

        changed = False
        for block in self._graph.nodes:
            kept = []
            for stmt in block.statements:
                if self._is_dead_spill(stmt, collector.used):
                    changed = True
                    continue
                kept.append(stmt)
            if len(kept) != len(block.statements):
                block.statements = kept
        if changed:
            self.out_graph = self._graph

    @staticmethod
    def _is_dead_spill(stmt, used: set[int]) -> bool:
        if not isinstance(stmt, Assignment):
            return False
        dst = stmt.dst
        if not (isinstance(dst, VirtualVariable) and dst.was_stack and dst.stack_offset is not None):
            return False
        # the return address sits at offset 0; the spill area starts right above it
        if dst.stack_offset <= 0 or dst.varid in used:
            return False
        return isinstance(stmt.src, (VirtualVariable, Const))
