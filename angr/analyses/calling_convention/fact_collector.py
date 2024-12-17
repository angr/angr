from __future__ import annotations
from typing import Any

import pyvex
import claripy

from angr.block import Block
from angr.analyses.analysis import Analysis
from angr.analyses import AnalysesHub
from angr.knowledge_plugins.functions import Function
from angr.engines.light import SimEngineNostmtVEX, SimEngineLight, SpOffset
from angr.calling_conventions import SimRegArg
from .utils import is_sane_register_variable


class FactCollectorState:
    __slots__ = (
        "reg_reads",
        "reg_writes",
        "sp_offset",
        "stack_reads",
        "tmps",
    )

    def __init__(self):
        self.tmps = {}
        self.reg_reads = {}
        self.reg_writes = {}
        self.stack_reads = {}
        self.sp_offset = 0

    def register_read(self, offset: int, bits: int):
        if offset in self.reg_writes:
            return
        if offset not in self.reg_reads:
            self.reg_reads[offset] = bits
        else:
            self.reg_reads[offset] = max(self.reg_reads[offset], bits)

    def register_written(self, offset: int, bits: int):
        self.reg_writes[offset] = bits

    def stack_read(self, offset: int, bits: int):
        if offset not in self.stack_reads:
            self.stack_reads[offset] = bits
        else:
            self.stack_reads[offset] = max(self.stack_reads[offset], bits)

    def copy(self) -> FactCollectorState:
        new_state = FactCollectorState()
        new_state.tmps = self.tmps.copy()
        new_state.reg_reads = self.reg_reads.copy()
        new_state.stack_reads = self.stack_reads.copy()
        new_state.reg_writes = self.reg_writes.copy()
        new_state.sp_offset = self.sp_offset
        return new_state


class SimEngineFactsCollectorVEX(
    SimEngineNostmtVEX[FactCollectorState, claripy.ast.BV | claripy.ast.FP, None],
    SimEngineLight[type[FactCollectorState], claripy.ast.BV | claripy.ast.FP, Block, None],
):
    def __init__(self, project):
        super().__init__(project)

    def _process_block_end(self, stmt_result: list, whitelist: set[int] | None) -> None:
        if self.block.vex.jumpkind == "Ijk_Call":
            self.state.register_written(self.arch.ret_offset, self.arch.bits)

    def _top(self, bits: int):
        return None

    def _is_top(self, expr: Any) -> bool:
        raise NotImplementedError

    def _handle_conversion(self, from_size: int, to_size: int, signed: bool, operand: pyvex.IRExpr) -> Any:
        return None

    def _handle_stmt_Put(self, stmt):
        v = self._expr(stmt.data)
        if stmt.offset == self.arch.sp_offset:
            if isinstance(v, SpOffset):
                self.state.sp_offset = v.offset
        else:
            self.state.register_written(stmt.offset, stmt.data.result_size(self.tyenv))

    def _handle_stmt_WrTmp(self, stmt: pyvex.IRStmt.WrTmp):
        v = self._expr(stmt.data)
        if v is not None:
            self.state.tmps[stmt.tmp] = v

    def _handle_expr_Const(self, expr: pyvex.IRExpr.Const):
        return expr.con.value

    def _handle_expr_GSPTR(self, expr):
        return None

    def _handle_expr_Get(self, expr) -> SpOffset | None:
        if expr.offset == self.arch.sp_offset:
            return SpOffset(self.arch.bits, self.state.sp_offset, is_base=False)
        self.state.register_read(expr.offset, expr.result_size(self.tyenv))
        return None

    def _handle_expr_GetI(self, expr):
        return None

    def _handle_expr_ITE(self, expr):
        return None

    def _handle_expr_Load(self, expr):
        return None

    def _handle_expr_RdTmp(self, expr):
        return None

    def _handle_expr_VECRET(self, expr):
        return None


class FactCollector(Analysis):
    """
    An extremely fast analysis that extracts necessary facts of a function for CallingConventionAnalysis to make
    decision on the calling convention and prototype of a function.
    """

    def __init__(self, func: Function, max_depth: int = 5):
        self.function = func
        self._max_depth = max_depth

        self.input_args = None

        self._analyze()

    def _analyze(self):
        # breadth-first search using function graph, collect registers and stack variables that are written to as well
        # as read from, until max_depth is reached

        func_graph = self.function.graph
        startpoint = self.function.startpoint
        engine = SimEngineFactsCollectorVEX(self.project)
        init_state = FactCollectorState()

        traversed = set()
        queue = [(0, init_state, startpoint)]
        end_states = []
        while queue:
            depth, state, node = queue.pop(0)
            traversed.add(node)

            if depth > self._max_depth:
                break

            block = self.project.factory.block(node.addr, size=node.size)
            engine.process(state, block=block)

            successor_added = False
            for succ in func_graph.successors(node):
                if succ not in traversed and depth + 1 <= self._max_depth:
                    successor_added = True
                    queue.append((depth + 1, state.copy(), succ))

            if not successor_added:
                end_states.append(state)

        self.input_args = []
        created = set()
        for state in end_states:
            for offset, bits in state.reg_reads.items():
                if (
                    offset in created
                    or offset == self.project.arch.bp_offset
                    or not is_sane_register_variable(self.project.arch, offset, bits // self.project.arch.byte_width)
                ):
                    continue
                created.add(offset)
                reg_name = self.project.arch.translate_register_name(offset, size=self.project.arch.bytes)
                arg = SimRegArg(reg_name, self.project.arch.bytes)
                self.input_args.append(arg)


AnalysesHub.register_default("FunctionFactCollector", FactCollector)
