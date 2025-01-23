from __future__ import annotations
from typing import Any

import pyvex
import claripy

from angr.utils.bits import s2u, u2s
from angr.block import Block
from angr.analyses.analysis import Analysis
from angr.analyses import AnalysesHub
from angr.knowledge_plugins.functions import Function
from angr.codenode import BlockNode, HookNode
from angr.engines.light import SimEngineNostmtVEX, SimEngineLight, SpOffset, RegisterOffset
from angr.calling_conventions import SimRegArg, SimStackArg, default_cc
from angr.sim_type import SimTypeBottom
from .utils import is_sane_register_variable


class FactCollectorState:
    """
    The abstract state for FactCollector.
    """

    __slots__ = (
        "bp_value",
        "callee_stored_regs",
        "reg_reads",
        "reg_writes",
        "simple_stack",
        "sp_value",
        "stack_reads",
        "stack_writes",
        "tmps",
    )

    def __init__(self):
        self.tmps = {}
        self.simple_stack = {}

        self.callee_stored_regs: dict[int, int] = {}  # reg offset -> stack offset
        self.reg_reads = {}
        self.reg_writes: set[int] = set()
        self.stack_reads = {}
        self.stack_writes: set[int] = set()
        self.sp_value = 0
        self.bp_value = 0

    def register_read(self, offset: int, size_in_bytes: int):
        if offset in self.reg_writes:
            return
        if offset not in self.reg_reads:
            self.reg_reads[offset] = size_in_bytes
        else:
            self.reg_reads[offset] = max(self.reg_reads[offset], size_in_bytes)

    def register_written(self, offset: int, size_in_bytes: int):
        for o in range(size_in_bytes):
            self.reg_writes.add(offset + o)

    def stack_read(self, offset: int, size_in_bytes: int):
        if offset in self.stack_writes:
            return
        if offset not in self.stack_reads:
            self.stack_reads[offset] = size_in_bytes
        else:
            self.stack_reads[offset] = max(self.stack_reads[offset], size_in_bytes)

    def stack_written(self, offset: int, size_int_bytes: int):
        for o in range(size_int_bytes):
            self.stack_writes.add(offset + o)

    def copy(self, with_tmps: bool = False) -> FactCollectorState:
        new_state = FactCollectorState()
        new_state.reg_reads = self.reg_reads.copy()
        new_state.stack_reads = self.stack_reads.copy()
        new_state.stack_writes = self.stack_writes.copy()
        new_state.reg_writes = self.reg_writes.copy()
        new_state.callee_stored_regs = self.callee_stored_regs.copy()
        new_state.sp_value = self.sp_value
        new_state.bp_value = self.bp_value
        new_state.simple_stack = self.simple_stack.copy()
        if with_tmps:
            new_state.tmps = self.tmps.copy()
        return new_state


binop_handler = SimEngineNostmtVEX[FactCollectorState, claripy.ast.BV, FactCollectorState].binop_handler


class SimEngineFactCollectorVEX(
    SimEngineNostmtVEX[FactCollectorState, SpOffset | RegisterOffset | int, None],
    SimEngineLight[type[FactCollectorState], SpOffset | RegisterOffset | int, Block, None],
):
    """
    THe engine for FactCollector.
    """

    def __init__(self, project, bp_as_gpr: bool):
        self.bp_as_gpr = bp_as_gpr
        super().__init__(project)

    def _process_block_end(self, stmt_result: list, whitelist: set[int] | None) -> None:
        if self.block.vex.jumpkind == "Ijk_Call":
            self.state.register_written(self.arch.ret_offset, self.arch.bytes)

    def _top(self, bits: int):
        return None

    def _is_top(self, expr: Any) -> bool:
        raise NotImplementedError

    def _handle_conversion(self, from_size: int, to_size: int, signed: bool, operand: pyvex.IRExpr) -> Any:
        return None

    def _handle_stmt_Put(self, stmt):
        v = self._expr(stmt.data)
        if stmt.offset == self.arch.sp_offset and isinstance(v, SpOffset):
            self.state.sp_value = v.offset
        elif stmt.offset == self.arch.bp_offset and isinstance(v, SpOffset):
            self.state.bp_value = v.offset
        else:
            self.state.register_written(stmt.offset, stmt.data.result_size(self.tyenv) // self.arch.byte_width)

    def _handle_stmt_Store(self, stmt: pyvex.IRStmt.Store):
        addr = self._expr(stmt.addr)
        if isinstance(addr, SpOffset):
            self.state.stack_written(addr.offset, stmt.data.result_size(self.tyenv) // self.arch.byte_width)
            data = self._expr(stmt.data)
            if isinstance(data, RegisterOffset) and not isinstance(data, SpOffset):
                # push reg; we record the stored register as well as the stack slot offset
                self.state.callee_stored_regs[data.reg] = u2s(addr.offset, self.arch.bits)
            if isinstance(data, SpOffset):
                self.state.simple_stack[addr.offset] = data

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
            return SpOffset(self.arch.bits, self.state.sp_value, is_base=False)
        if expr.offset == self.arch.bp_offset and not self.bp_as_gpr:
            return SpOffset(self.arch.bits, self.state.bp_value, is_base=False)
        bits = expr.result_size(self.tyenv)
        self.state.register_read(expr.offset, bits // self.arch.byte_width)
        return RegisterOffset(bits, expr.offset, 0)

    def _handle_expr_GetI(self, expr):
        return None

    def _handle_expr_ITE(self, expr):
        return None

    def _handle_expr_Load(self, expr):
        addr = self._expr(expr.addr)
        if isinstance(addr, SpOffset):
            self.state.stack_read(addr.offset, expr.result_size(self.tyenv) // self.arch.byte_width)
            return self.state.simple_stack.get(addr.offset)
        return None

    def _handle_expr_RdTmp(self, expr):
        return self.state.tmps.get(expr.tmp, None)

    def _handle_expr_VECRET(self, expr):
        return None

    @binop_handler
    def _handle_binop_Add(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if isinstance(op0, SpOffset) and isinstance(op1, int):
            return SpOffset(op0.bits, s2u(op0.offset + op1, op0.bits), is_base=op0.is_base)
        if isinstance(op1, SpOffset) and isinstance(op0, int):
            return SpOffset(op1.bits, s2u(op1.offset + op0, op1.bits), is_base=op1.is_base)
        return None

    @binop_handler
    def _handle_binop_Sub(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if isinstance(op0, SpOffset) and isinstance(op1, int):
            return SpOffset(op0.bits, s2u(op0.offset - op1, op0.bits), is_base=op0.is_base)
        if isinstance(op1, SpOffset) and isinstance(op0, int):
            return SpOffset(op1.bits, s2u(op1.offset - op0, op1.bits), is_base=op1.is_base)
        return None

    @binop_handler
    def _handle_binop_And(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if isinstance(op0, SpOffset):
            return op0
        if isinstance(op1, SpOffset):
            return op1
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

        end_states = self._analyze_startpoint()
        self._analyze_endpoints_for_retval_size()
        callee_restored_regs = self._analyze_endpoints_for_restored_regs()
        self._determine_input_args(end_states, callee_restored_regs)

    def _analyze_startpoint(self):
        func_graph = self.function.transition_graph
        startpoint = self.function.startpoint
        bp_as_gpr = self.function.info.get("bp_as_gpr", False)
        engine = SimEngineFactCollectorVEX(self.project, bp_as_gpr)
        init_state = FactCollectorState()
        if self.project.arch.call_pushes_ret:
            init_state.sp_value = self.project.arch.bytes
        init_state.bp_value = init_state.sp_value

        traversed = set()
        queue: list[tuple[int, FactCollectorState, BlockNode | HookNode | Function, BlockNode | HookNode | None]] = [
            (0, init_state, startpoint, None)
        ]
        end_states: list[FactCollectorState] = []
        while queue:
            depth, state, node, retnode = queue.pop(0)
            traversed.add(node)

            if depth > self._max_depth:
                end_states.append(state)
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
                    new_state = state.copy()
                    if self.project.arch.call_pushes_ret:
                        new_state.sp_value += self.project.arch.bytes
                    queue.append((depth, new_state, retnode, None))
                continue

            block = self.project.factory.block(node.addr, size=node.size)
            engine.process(state, block=block)

            successor_added = False
            call_succ, ret_succ = None, None
            for _, succ, data in func_graph.out_edges(node, data=True):
                edge_type = data.get("type")
                outside = data.get("outside", False)
                if succ not in traversed and depth + 1 <= self._max_depth:
                    if edge_type == "fake_return":
                        ret_succ = succ
                    elif edge_type == "transition" and not outside:
                        successor_added = True
                        queue.append((depth + 1, state.copy(), succ, None))
                    elif edge_type == "call" or (edge_type == "transition" and outside):
                        # a call or a tail-call
                        if not isinstance(succ, Function):
                            if self.kb.functions.contains_addr(succ.addr):
                                succ = self.kb.functions.get_by_addr(succ.addr)
                            else:
                                # not sure who we are calling
                                continue
                        call_succ = succ
            if call_succ is not None:
                successor_added = True
                queue.append((depth + 1, state.copy(), call_succ, ret_succ))

            if not successor_added:
                end_states.append(state)

        return end_states

    def _handle_function(self, state: FactCollectorState, func: Function) -> None:
        try:
            arg_locs = func.calling_convention.arg_locs(func.prototype)
        except (TypeError, ValueError):
            return

        if None in arg_locs:
            return

        for arg_loc in arg_locs:
            for loc in arg_loc.get_footprint():
                if isinstance(loc, SimRegArg):
                    state.register_read(self.project.arch.registers[loc.reg_name][0] + loc.reg_offset, loc.size)
                elif isinstance(loc, SimStackArg):
                    sp_value = state.sp_value
                    if sp_value is not None:
                        state.stack_read(sp_value + loc.stack_offset, loc.size)

        # clobber caller-saved regs
        for reg_name in func.calling_convention.CALLER_SAVED_REGS:
            offset = self.project.arch.registers[reg_name][0]
            state.register_written(offset, self.project.arch.registers[reg_name][1])

    def _analyze_endpoints_for_retval_size(self):
        """
        Analyze all endpoints to determine the return value size.
        """
        func_graph = self.function.transition_graph
        cc_cls = default_cc(
            self.project.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )
        if cc_cls is None:
            # don't know what the calling convention may be... give up
            return
        cc = cc_cls(self.project.arch)
        if isinstance(cc.RETURN_VAL, SimRegArg):
            retreg_offset = cc.RETURN_VAL.check_offset(self.project.arch)
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
                    if isinstance(stmt, pyvex.IRStmt.Put):
                        size = stmt.data.result_size(block.vex.tyenv) // self.project.arch.byte_width
                        if stmt.offset == retreg_offset:
                            retval_size = max(size, 1)

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

    def _analyze_endpoints_for_restored_regs(self):
        """
        Analyze all endpoints to determine the restored registers.
        """
        func_graph = self.function.transition_graph
        callee_restored_regs = set()

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
                if isinstance(node, (HookNode, Function)):
                    continue

                block = self.project.factory.block(node.addr, size=node.size)
                # scan the block statements backwards to find all statements that restore registers from the stack
                tmps = {}
                for stmt in block.vex.statements:
                    if isinstance(stmt, pyvex.IRStmt.WrTmp):
                        if isinstance(stmt.data, pyvex.IRExpr.Get) and stmt.data.offset in {
                            self.project.arch.bp_offset,
                            self.project.arch.sp_offset,
                        }:
                            tmps[stmt.tmp] = "sp"
                        elif (
                            isinstance(stmt.data, pyvex.IRExpr.Load)
                            and isinstance(stmt.data.addr, pyvex.IRExpr.RdTmp)
                            and tmps.get(stmt.data.addr.tmp) == "sp"
                        ):
                            tmps[stmt.tmp] = "stack_value"
                        elif isinstance(stmt.data, pyvex.IRExpr.Const):
                            tmps[stmt.tmp] = "const"
                        elif isinstance(stmt.data, pyvex.IRExpr.Binop) and (  # noqa:SIM102
                            stmt.data.op.startswith("Iop_Add") or stmt.data.op.startswith("Iop_Sub")
                        ):
                            if (
                                isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp)
                                and tmps.get(stmt.data.args[0].tmp) == "sp"
                            ) or (
                                isinstance(stmt.data.args[1], pyvex.IRExpr.RdTmp)
                                and tmps.get(stmt.data.args[1].tmp) == "sp"
                            ):
                                tmps[stmt.tmp] = "sp"
                    if isinstance(stmt, pyvex.IRStmt.Put):
                        size = stmt.data.result_size(block.vex.tyenv) // self.project.arch.byte_width
                        # is the data loaded from the stack?
                        if (
                            size == self.project.arch.bytes
                            and isinstance(stmt.data, pyvex.IRExpr.RdTmp)
                            and tmps.get(stmt.data.tmp) == "stack_value"
                        ):
                            callee_restored_regs.add(stmt.offset)

                for pred, _, data in func_graph.in_edges(node, data=True):
                    edge_type = data.get("type")
                    if pred not in traversed and depth + 1 <= self._max_depth and edge_type == "transition":
                        queue.append((depth + 1, pred))

        # remove offsets of registers that may store return values from callee_restored_regs
        ret_reg_offsets = set()
        cc_cls = default_cc(
            self.project.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )
        if cc_cls is not None:
            cc = cc_cls(self.project.arch)
            if isinstance(cc.RETURN_VAL, SimRegArg):
                retreg_offset = cc.RETURN_VAL.check_offset(self.project.arch)
                ret_reg_offsets.add(retreg_offset)
            if isinstance(cc.OVERFLOW_RETURN_VAL, SimRegArg):
                retreg_offset = cc.OVERFLOW_RETURN_VAL.check_offset(self.project.arch)
                ret_reg_offsets.add(retreg_offset)
            if isinstance(cc.FP_RETURN_VAL, SimRegArg):
                try:
                    retreg_offset = cc.FP_RETURN_VAL.check_offset(self.project.arch)
                    ret_reg_offsets.add(retreg_offset)
                except KeyError:
                    # register name does not exist
                    pass

        return callee_restored_regs.difference(ret_reg_offsets)

    def _determine_input_args(self, end_states: list[FactCollectorState], callee_restored_regs: set[int]) -> None:
        self.input_args = []
        reg_offset_created = set()
        callee_saved_regs = set()
        callee_saved_reg_stack_offsets = set()

        # determine callee-saved registers
        for state in end_states:
            for reg_offset, stack_offset in state.callee_stored_regs.items():
                if reg_offset in callee_restored_regs:
                    callee_saved_regs.add(reg_offset)
                    callee_saved_reg_stack_offsets.add(stack_offset)

        for state in end_states:
            for offset, size in state.reg_reads.items():
                if (
                    offset in reg_offset_created
                    or offset == self.project.arch.bp_offset
                    or not is_sane_register_variable(self.project.arch, offset, size)
                    or offset in callee_saved_regs
                ):
                    continue
                reg_offset_created.add(offset)
                if self.project.arch.name in {"AMD64", "X86"} and size < self.project.arch.bytes:
                    # use complete registers on AMD64 and X86
                    reg_name = self.project.arch.translate_register_name(offset, size=self.project.arch.bytes)
                    arg = SimRegArg(reg_name, self.project.arch.bytes)
                else:
                    reg_name = self.project.arch.translate_register_name(offset, size=size)
                    arg = SimRegArg(reg_name, size)
                self.input_args.append(arg)

        stack_offset_created = set()
        ret_addr_offset = 0 if not self.project.arch.call_pushes_ret else self.project.arch.bytes
        for state in end_states:
            for offset, size in state.stack_reads.items():
                offset = u2s(offset, self.project.arch.bits)
                if offset - ret_addr_offset > 0:
                    if offset in stack_offset_created or offset in callee_saved_reg_stack_offsets:
                        continue
                    stack_offset_created.add(offset)
                    arg = SimStackArg(offset - ret_addr_offset, size)
                    self.input_args.append(arg)


AnalysesHub.register_default("FunctionFactCollector", FactCollector)
