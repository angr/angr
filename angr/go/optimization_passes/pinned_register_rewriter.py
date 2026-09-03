from __future__ import annotations

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import Const, Register
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage

# registers the Go ABI pins to a fixed meaning; only the zero register can be folded into a constant
_ZERO_REGISTERS = {
    "AMD64": "xmm15",
    "AARCH64": "xzr",
}


class _RegisterWriteFinder(AILBlockViewer):
    """Record whether any statement writes the register at ``reg_offset``."""

    def __init__(self, reg_offset: int, reg_size: int):
        super().__init__()
        self._lo = reg_offset
        self._hi = reg_offset + reg_size
        self.written = False

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block):
        dst = stmt.dst
        if isinstance(dst, Register) and self._lo <= dst.reg_offset < self._hi:
            self.written = True
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)


class _ZeroRegisterRewriter(AILBlockRewriter):
    """Replace every read of the register at ``reg_offset`` with a zero constant."""

    def __init__(self, manager, reg_offset: int, reg_size: int):
        super().__init__()
        self._manager = manager
        self._lo = reg_offset
        self._hi = reg_offset + reg_size
        self.changed = False

    def _handle_Register(self, expr_idx: int, expr: Register, stmt_idx: int, stmt, block):
        if self._lo <= expr.reg_offset < self._hi:
            self.changed = True
            return Const(self._manager.next_atom(), 0, expr.bits, **expr.tags)
        return expr


class GoPinnedRegisterRewriter(OptimizationPass):
    """
    Fold reads of the ABI zero register (X15 on amd64) into the constant 0.

    Compiled Go code never writes the zero register, so its reads are the constant 0 rather than an undefined
    input; leaving them alone turns every zero-initialization into a phantom parameter.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Fold the Go zero register into constants"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary and self.project.arch.name in _ZERO_REGISTERS, None

    def _analyze(self, cache=None):
        reg_name = _ZERO_REGISTERS[self.project.arch.name]
        if reg_name not in self.project.arch.registers:
            return
        reg_offset, reg_size = self.project.arch.registers[reg_name]

        # a function that writes the register (hand-written assembly) is not using it as a zero register
        finder = _RegisterWriteFinder(reg_offset, reg_size)
        for block in self._graph.nodes:
            finder.walk(block)
            if finder.written:
                return

        rewriter = _ZeroRegisterRewriter(self.manager, reg_offset, reg_size)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        if rewriter.changed:
            self.out_graph = self._graph
