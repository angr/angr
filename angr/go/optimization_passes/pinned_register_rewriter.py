from __future__ import annotations

from typing import cast

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import BinaryOp, Call, Const, Register, StackBaseOffset
from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.utils.names import call_target_name
from angr.utils.ail import find_call
from angr.utils.go_runtime import normalize_go_func_name

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


class GoWideZeroStoreSplitter(OptimizationPass):
    """
    ``MOVUPS X15, off(SP)`` zeroes two words of a frame slot at once. Split it into word stores so the words of a
    slice/string header kept in the frame stay separate stack variables instead of one 16-byte variable that every
    later word write updates with an insert.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL1_TRANSFORMATION
    NAME = "Split Go wide zero stores into words"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary and self.project.arch.name == "AMD64", None

    def _analyze(self, cache=None):
        # only where a slice grows: defer records and other frame structs are zeroed the same way and are matched
        # as wide stores later
        if not self._calls_growslice():
            return
        ws = self.project.arch.bytes
        changed = False
        for block in self._graph.nodes:
            # only a three-word value (a slice header) zeroed as one word plus one wide store: a lone wide store is
            # a two-word value (string, interface) that is better kept whole
            words = {self._zero_store_at(st, ws) for st in block.statements} - {None}
            wide = {self._zero_store_at(st, 2 * ws) for st in block.statements} - {None}
            zeroed = words | wide
            new_stmts = []
            hit = False
            for stmt in block.statements:
                base = self._zero_store_at(stmt, 2 * ws)
                if base is not None and (
                    (base - ws in words and base + 2 * ws not in zeroed and base - 2 * ws not in zeroed)
                    or (
                        base + 2 * ws in words
                        and base - ws not in zeroed
                        and base - 2 * ws not in zeroed
                        and base + 3 * ws not in zeroed
                    )
                ):
                    for k in range(2):
                        # each store needs its own StackBaseOffset: SSA keys stack definitions by that node
                        addr = StackBaseOffset(
                            self.manager.next_atom(), stmt.addr.bits, base + k * ws, **stmt.addr.tags
                        )
                        zero = Const(self.manager.next_atom(), 0, ws * 8, **stmt.data.tags)
                        idx = stmt.idx if not k else self.manager.next_atom()
                        new_stmts.append(Store(idx, addr, zero, ws, stmt.endness, **stmt.tags))
                    hit = True
                    continue
                new_stmts.append(stmt)
            if hit:
                block.statements = new_stmts
                changed = True
        if changed:
            self.out_graph = self._graph

    def _calls_growslice(self) -> bool:
        for block in self._graph.nodes:
            for stmt in block.statements:
                call = find_call(stmt)
                if call is not None:
                    name = call_target_name(self.project, cast(Call, call))
                    if name is not None and normalize_go_func_name(name) in (
                        "runtime.growslice",
                        "runtime.growsliceBuf",
                    ):
                        return True
        return False

    def _zero_store_at(self, stmt, size: int) -> int | None:
        """The frame offset a zero store of ``size`` bytes writes to."""
        if not (isinstance(stmt, Store) and stmt.size == size and isinstance(stmt.data, Const) and stmt.data.is_int):
            return None
        return self._stack_offset(stmt.addr) if stmt.data.value_int == 0 else None

    @staticmethod
    def _stack_offset(addr) -> int | None:
        if isinstance(addr, StackBaseOffset):
            return addr.offset
        if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[0], StackBaseOffset):
            k = addr.operands[1]
            if isinstance(k, Const) and k.is_int:
                return addr.operands[0].offset + k.value_int
        return None
