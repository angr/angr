from __future__ import annotations
from typing import Any

import pyvex
import claripy

from angr.block import Block
from angr.analyses.analysis import Analysis
from angr.analyses import AnalysesHub
from angr.knowledge_plugins.functions import Function
from angr.codenode import BlockNode, HookNode
from angr.engines.light import SimEngineNostmtVEX, SimEngineLight, SpOffset
from angr.calling_conventions import SimRegArg, SimStackArg, default_cc
from angr.sim_type import SimTypeBottom
from .utils import is_sane_register_variable


class FactCollectorState:
    """
    The abstract state for FactCollector.
    """

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


class SimEngineFactCollectorVEX(
    SimEngineNostmtVEX[FactCollectorState, claripy.ast.BV | claripy.ast.FP, None],
    SimEngineLight[type[FactCollectorState], claripy.ast.BV | claripy.ast.FP, Block, None],
):
    """
    THe engine for FactCollector.
    """

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

        self.input_args: list[SimRegArg | SimStackArg] | None = None
        self.retval_size: int | None = None

        self._analyze()

    def _analyze(self):
        # breadth-first search using function graph, collect registers and stack variables that are written to as well
        # as read from, until max_depth is reached

        self._analyze_startpoint()
        self._analyze_endpoints()

    def _analyze_startpoint(self):
        func_graph = self.function.transition_graph
        startpoint = self.function.startpoint
        engine = SimEngineFactCollectorVEX(self.project)
        init_state = FactCollectorState()

        traversed = set()
        queue: list[tuple[int, FactCollectorState, BlockNode | HookNode | Function, BlockNode | HookNode | None]] = [
            (0, init_state, startpoint, None)
        ]
        end_states: list[FactCollectorState] = []
        while queue:
            depth, state, node, retnode = queue.pop(0)
            traversed.add(node)

            if depth > self._max_depth:
                break

            if isinstance(node, BlockNode) and node.size == 0:
                continue
            if isinstance(node, HookNode):
                # attempt to convert it into a function
                if self.kb.functions.contains_addr(node.addr):
                    node = self.kb.functions.get_by_addr(node.addr)
                else:
                    continue
            if isinstance(node, Function):
                if node.calling_convention is not None and node.prototype is not None:
                    # consume args and overwrite the return register
                    self._handle_function(state, node)
                    if node.returning is False or retnode is None:
                        # the function call does not return
                        end_states.append(state)
                    else:
                        # enqueue the retnode, but we don't increment the depth
                        queue.append((depth, state.copy(), retnode, None))
                continue

            block = self.project.factory.block(node.addr, size=node.size)
            engine.process(state, block=block)

            successor_added = False
            for _, succ, data in func_graph.out_edges(node, data=True):
                edge_type = data.get("type")
                call_succ, ret_succ = None, None
                if succ not in traversed and depth + 1 <= self._max_depth:
                    if edge_type == "fake_return":
                        ret_succ = succ
                    elif edge_type == "transition":
                        successor_added = True
                        queue.append((depth + 1, state.copy(), succ, None))
                    elif edge_type == "call":
                        call_succ = succ
                if call_succ is not None:
                    successor_added = True
                    queue.append((depth + 1, state.copy(), call_succ, ret_succ))

            if not successor_added:
                end_states.append(state)

        self.input_args = []
        reg_offset_created = set()
        for state in end_states:
            for offset, bits in state.reg_reads.items():
                if (
                    offset in reg_offset_created
                    or offset == self.project.arch.bp_offset
                    or not is_sane_register_variable(self.project.arch, offset, bits // self.project.arch.byte_width)
                ):
                    continue
                reg_offset_created.add(offset)
                reg_name = self.project.arch.translate_register_name(offset, size=self.project.arch.bytes)
                arg = SimRegArg(reg_name, self.project.arch.bytes)
                self.input_args.append(arg)

        stack_offset_created = set()
        ret_addr_offset = 0 if not self.project.arch.call_pushes_ret else self.project.arch.bytes
        for state in end_states:
            for offset, size in state.stack_reads.items():
                if offset - ret_addr_offset >= 0:
                    if offset in stack_offset_created:
                        continue
                    stack_offset_created.add(offset)
                    arg = SimStackArg(offset - ret_addr_offset, size)
                    self.input_args.append(arg)

    def _handle_function(self, state: FactCollectorState, func: Function) -> None:
        try:
            arg_locs = func.calling_convention.arg_locs(func.prototype)
        except (TypeError, ValueError):
            func.prototype = None
            return

        if None in arg_locs:
            return

        for arg_loc in arg_locs:
            for loc in arg_loc.get_footprint():
                if isinstance(loc, SimRegArg):
                    state.register_read(self.project.arch.registers[loc.reg_name][0] + loc.reg_offset, loc.size)
                elif isinstance(loc, SimStackArg):
                    sp_offset = state.sp_offset
                    if sp_offset is not None:
                        state.stack_read(sp_offset + loc.stack_offset, loc.size)

    def _analyze_endpoints(self):
        """
        Analyze all endpoints to determine the return value size.
        """
        func_graph = self.function.transition_graph
        cc_cls = default_cc(
            self.project.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )
        cc = cc_cls(self.project.arch)
        if isinstance(cc.RETURN_VAL, SimRegArg):
            reg_offset = cc.RETURN_VAL.check_offset(self.project.arch)
        else:
            return

        retval_sizes = []
        for endpoint in self.function.endpoints:
            traversed = set()
            queue: list[tuple[int, BlockNode | HookNode]] = [(0, endpoint)]
            while queue:
                depth, node = queue.pop(0)
                traversed.add(node)

                if depth > 3:
                    break

                if isinstance(node, BlockNode) and node.size == 0:
                    continue
                if isinstance(node, HookNode):
                    # attempt to convert it into a function
                    if self.kb.functions.contains_addr(node.addr):
                        node = self.kb.functions.get_by_addr(node.addr)
                    else:
                        continue
                if isinstance(node, Function):
                    if (
                        node.calling_convention is not None
                        and node.prototype is not None
                        and node.prototype.returnty is not None
                        and not isinstance(node.prototype.returnty, SimTypeBottom)
                    ):
                        # assume the function overwrites the return variable
                        retval_size = (
                            node.prototype.returnty.with_arch(self.project.arch).size // self.project.arch.byte_width
                        )
                        retval_sizes.append(retval_size)
                    continue

                block = self.project.factory.block(node.addr, size=node.size)
                # scan the block statements backwards to find writes to the return value register
                retval_size = None
                for stmt in reversed(block.vex.statements):
                    if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == reg_offset:
                        retval_size = max(stmt.data.result_size(block.vex.tyenv) // self.project.arch.byte_width, 1)
                        break

                if retval_size is not None:
                    retval_sizes.append(retval_size)
                    continue

                for pred, _, data in func_graph.in_edges(node, data=True):
                    edge_type = data.get("type")
                    if pred not in traversed and depth + 1 <= self._max_depth:
                        if edge_type == "fake_return":
                            continue
                        if edge_type in {"transition", "call"}:
                            queue.append((depth + 1, pred))

        self.retval_size = max(retval_sizes) if retval_sizes else None


AnalysesHub.register_default("FunctionFactCollector", FactCollector)
