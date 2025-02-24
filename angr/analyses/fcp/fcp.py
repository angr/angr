from __future__ import annotations
from typing import Any
from collections.abc import Callable
from collections import defaultdict

import networkx
import pyvex
import claripy

from angr.utils.bits import s2u
from angr.block import Block
from angr.analyses.analysis import Analysis
from angr.analyses import AnalysesHub
from angr.knowledge_plugins.functions import Function
from angr.codenode import BlockNode, HookNode
from angr.engines.light import SimEngineNostmtVEX, SimEngineLight, SpOffset, RegisterOffset
from angr.calling_conventions import SimStackArg, default_cc
from angr.analyses.propagator.vex_vars import VEXReg, VEXTmp


class SV:
    """
    SizedValue: A faster implementation of claripy.ast.BV.
    """

    __slots__ = ("bits", "value")

    def __init__(self, value, bits):
        self.value = value
        self.bits = bits

    def __eq__(self, other):
        return isinstance(other, SV) and self.value == other.value and self.bits == other.bits

    def __hash__(self):
        return hash((self.value, self.bits))


class FCPState:
    """
    The abstract state for FastConstantPropagation.
    """

    __slots__ = (
        "bp_value",
        "callee_stored_regs",
        "regs",
        "simple_stack",
        "sp_value",
        "stack",
        "tmps",
    )

    def __init__(self):
        self.tmps = {}
        self.simple_stack = {}

        self.regs: dict[int, SV] = {}
        self.stack: dict[int, SV] = {}
        self.sp_value = 0
        self.bp_value = 0

    def register_read(self, offset, size_in_bytes: int) -> int | None:
        if offset in self.regs:
            v = self.regs[offset]
            if v.bits == size_in_bytes * 8:
                return v.value
        return None

    def register_written(self, offset: int, size_in_bytes: int, value: int | None):
        if value is None:
            to_remove = set()
            for off, v in self.regs.items():
                if (off <= offset < off + v.bits // 8) or (offset <= off < offset + size_in_bytes):
                    to_remove.add(off)
            for off in to_remove:
                del self.regs[off]
        else:
            self.regs[offset] = SV(value, size_in_bytes * 8)

    def stack_read(self, offset: int, size_int_bytes: int) -> int | None:
        if offset in self.stack:
            v = self.stack[offset]
            if v.bits == size_int_bytes * 8:
                return v.value
        return None

    def stack_written(self, offset: int, size_int_bytes: int, value: int | None):
        if value is None:
            to_remove = set()
            for off, v in self.stack.items():
                if (off <= offset < off + v.bits // 8) or (offset <= off < offset + size_int_bytes):
                    to_remove.add(off)
            for off in to_remove:
                del self.stack[off]
        else:
            self.stack[offset] = SV(value, size_int_bytes * 8)

    def copy(self, with_tmps: bool = False) -> FCPState:
        new_state = FCPState()
        new_state.stack = self.stack.copy()
        new_state.regs = self.regs.copy()
        new_state.sp_value = self.sp_value
        new_state.bp_value = self.bp_value
        new_state.simple_stack = self.simple_stack.copy()
        if with_tmps:
            new_state.tmps = self.tmps.copy()
        return new_state


binop_handler = SimEngineNostmtVEX[FCPState, claripy.ast.BV, FCPState].binop_handler


class SimEngineFCPVEX(
    SimEngineNostmtVEX[FCPState, SpOffset | RegisterOffset | int, None],
    SimEngineLight[type[FCPState], SpOffset | RegisterOffset | int, Block, None],
):
    """
    THe engine for FastConstantPropagation.
    """

    def __init__(self, project, bp_as_gpr: bool, replacements: dict[int, dict], load_callback: Callable | None = None):
        self.bp_as_gpr = bp_as_gpr
        self.replacements = replacements
        self._load_callback = load_callback
        self.base_state = None
        super().__init__(project)

    def _allow_loading(self, addr: int, size: int) -> bool:
        if self._load_callback is None:
            return True
        return self._load_callback(addr, size)

    def _process_block_end(self, stmt_result: list, whitelist: set[int] | None) -> None:
        if self.block.vex.jumpkind == "Ijk_Call":
            self.state.register_written(self.arch.ret_offset, self.arch.bytes, None)

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
        elif stmt.offset == self.arch.bp_offset and not self.bp_as_gpr and isinstance(v, SpOffset):
            self.state.bp_value = v.offset
        elif isinstance(v, int):
            size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
            codeloc = self._codeloc()
            self.state.register_written(stmt.offset, size, v)
            if stmt.offset != self.arch.ip_offset:
                self.replacements[codeloc][VEXReg(stmt.offset, size)] = v
        else:
            size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
            self.state.register_written(stmt.offset, size, None)

    def _handle_stmt_Store(self, stmt: pyvex.IRStmt.Store):
        addr = self._expr(stmt.addr)
        if isinstance(addr, SpOffset):
            data = self._expr(stmt.data)
            if isinstance(data, int):
                self.state.stack_written(addr.offset, stmt.data.result_size(self.tyenv) // self.arch.byte_width, data)
            else:
                self.state.stack_written(addr.offset, stmt.data.result_size(self.tyenv) // self.arch.byte_width, None)

    def _handle_stmt_WrTmp(self, stmt: pyvex.IRStmt.WrTmp):
        if isinstance(stmt.data, pyvex.IRExpr.Binop) and not (
            stmt.data.op.startswith("Iop_Add")
            or stmt.data.op.startswith("Iop_Sub")
            or stmt.data.op.startswith("Iop_And")
        ):
            return
        v = self._expr(stmt.data)
        if v is not None:
            self.state.tmps[stmt.tmp] = v
            if isinstance(v, int):
                codeloc = self._codeloc()
                self.replacements[codeloc][VEXTmp(stmt.tmp)] = v

    def _handle_expr_Const(self, expr: pyvex.IRExpr.Const):
        return expr.con.value

    def _handle_expr_GSPTR(self, expr):
        return None

    def _handle_expr_Get(self, expr) -> SpOffset | None:
        if expr.offset == self.arch.sp_offset:
            return SpOffset(self.arch.bits, self.state.sp_value, is_base=False)
        if expr.offset == self.arch.bp_offset and not self.bp_as_gpr:
            return SpOffset(self.arch.bits, self.state.bp_value, is_base=False)
        size = expr.result_size(self.tyenv) // self.arch.byte_width
        v = self.state.register_read(expr.offset, size)
        if v is not None:
            codeloc = self._codeloc()
            self.replacements[codeloc][VEXReg(expr.offset, size)] = v
        return v

    def _handle_expr_GetI(self, expr):
        return None

    def _handle_expr_ITE(self, expr):
        return None

    def _handle_expr_Load(self, expr) -> int | SpOffset | None:
        addr = self._expr(expr.addr)
        if isinstance(addr, SpOffset):
            return self.state.stack.get(addr.offset)
        if isinstance(addr, int):
            size = expr.result_size(self.tyenv) // self.arch.byte_width
            if self._allow_loading(addr, size):
                # Try loading from the state
                if self.base_state is not None:
                    data = self.base_state.memory.load(addr, size, endness=expr.endness)
                    if not data.symbolic:
                        return data.args[0]
                else:
                    try:
                        return self.project.loader.memory.unpack_word(addr, size=size, endness=expr.endness)
                    except KeyError:
                        pass
        return None

    def _handle_expr_RdTmp(self, expr):
        return self.state.tmps.get(expr.tmp, None)

    def _dummy_handler(self, expr):  # pylint:disable=unused-argument,no-self-use
        return None

    _handle_expr_VECRET = _dummy_handler
    _handle_expr_CCall = _dummy_handler
    _handle_expr_Unop = _dummy_handler
    _handle_expr_Triop = _dummy_handler

    @binop_handler
    def _handle_binop_Add(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if isinstance(op0, SpOffset) and isinstance(op1, int):
            return SpOffset(op0.bits, s2u(op0.offset + op1, op0.bits), is_base=op0.is_base)
        if isinstance(op1, SpOffset) and isinstance(op0, int):
            return SpOffset(op1.bits, s2u(op1.offset + op0, op1.bits), is_base=op1.is_base)
        if isinstance(op0, int) and isinstance(op1, int):
            mask = (1 << expr.result_size(self.tyenv)) - 1
            return (op0 + op1) & mask
        return None

    @binop_handler
    def _handle_binop_Sub(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if isinstance(op0, SpOffset) and isinstance(op1, int):
            return SpOffset(op0.bits, s2u(op0.offset - op1, op0.bits), is_base=op0.is_base)
        if isinstance(op1, SpOffset) and isinstance(op0, int):
            return SpOffset(op1.bits, s2u(op1.offset - op0, op1.bits), is_base=op1.is_base)
        if isinstance(op0, int) and isinstance(op1, int):
            mask = (1 << expr.result_size(self.tyenv)) - 1
            return (op0 - op1) & mask
        return None

    @binop_handler
    def _handle_binop_And(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if isinstance(op0, SpOffset):
            return op0
        if isinstance(op1, SpOffset):
            return op1
        if isinstance(op0, int) and isinstance(op1, int):
            return op0 & op1
        return None


class FastConstantPropagation(Analysis):
    """
    An extremely fast constant propagation analysis that finds function-wide constant values with potentially high
    false negative rates.
    """

    def __init__(
        self,
        func: Function,
        blocks: set[Block] | None = None,
        vex_cross_insn_opt: bool = False,
        load_callback: Callable | None = None,
    ):
        self.function = func
        self._blocks = blocks
        self._vex_cross_insn_opt = vex_cross_insn_opt
        self._load_callback = load_callback

        self.replacements = {}

        self._analyze()

    def _analyze(self):
        # traverse the function graph, collect registers and stack variables that are written to
        func_graph = self.function.graph
        func_graph_with_callees = self.function.transition_graph
        startpoint = self.function.startpoint
        bp_as_gpr = self.function.info.get("bp_as_gpr", False)
        replacements = defaultdict(dict)
        engine = SimEngineFCPVEX(self.project, bp_as_gpr, replacements, load_callback=self._load_callback)
        init_state = FCPState()
        if self.project.arch.call_pushes_ret:
            init_state.sp_value = self.project.arch.bytes
        init_state.bp_value = init_state.sp_value

        sorted_nodes = reversed(list(networkx.dfs_postorder_nodes(func_graph, startpoint)))
        block_addrs = None
        if self._blocks:
            block_addrs = {b.addr for b in self._blocks}

        states: dict[BlockNode, FCPState] = {}
        for node in sorted_nodes:
            preds = func_graph.predecessors(node)
            input_states = [states[pred] for pred in preds if pred in states]
            state = init_state.copy() if not input_states else self._merge_states(input_states)

            if self._blocks and node.addr not in block_addrs:
                # skip this block
                states[node] = state
                continue

            # process the block
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
                continue

            block = self.project.factory.block(node.addr, size=node.size, cross_insn_opt=self._vex_cross_insn_opt)
            engine.process(state, block=block)

            # if the node ends with a function call, call _handle_function
            succs = list(func_graph_with_callees.successors(node))
            if any(isinstance(succ, (Function, HookNode)) for succ in succs):
                callee = next(succ for succ in succs if isinstance(succ, (Function, HookNode)))
                if isinstance(callee, HookNode):
                    # attempt to convert it into a function
                    if self.kb.functions.contains_addr(callee.addr):
                        callee = self.kb.functions.get_by_addr(callee.addr)
                    else:
                        callee = None
                state = self._handle_function(state, callee)

            states[node] = state

        self.replacements = replacements

    @staticmethod
    def _merge_states(states: list[FCPState]) -> FCPState:
        state = FCPState()
        to_drop = set()
        common_keys = set.intersection(*[set(s.regs) for s in states])
        for s in states:
            for offset, value in s.regs.items():
                if offset in common_keys:
                    if offset in state.regs:
                        if state.regs[offset] != value:
                            to_drop.add(offset)
                    else:
                        state.regs[offset] = value
        for offset in to_drop:
            del state.regs[offset]

        to_drop = set()
        common_keys = set.intersection(*[set(s.stack) for s in states])
        for s in states:
            for offset, value in s.stack.items():
                if offset in common_keys:
                    if offset in state.stack:
                        if state.stack[offset] != value:
                            to_drop.add(offset)
                    else:
                        state.stack[offset] = value
        for offset in to_drop:
            del state.stack[offset]

        for s in states:
            state.sp_value = max(state.sp_value, s.sp_value)
            state.bp_value = max(state.bp_value, s.bp_value)
        return state

    def _handle_function(self, state: FCPState, func: Function | None) -> FCPState:

        if func is None or func.calling_convention is None:
            cc = default_cc(self.project.arch.name)
        else:
            cc = func.calling_convention

        out_state = state.copy()
        if func is not None and func.prototype is not None:
            arg_locs = None
            try:
                arg_locs = cc.arg_locs(func.prototype)
            except (TypeError, ValueError):
                arg_locs = None

            if arg_locs is not None and None not in arg_locs:
                for arg_loc in arg_locs:
                    for loc in arg_loc.get_footprint():
                        if isinstance(loc, SimStackArg):
                            sp_value = out_state.sp_value
                            if sp_value is not None:
                                out_state.stack_read(sp_value + loc.stack_offset, loc.size)

        # clobber caller-saved regs
        for reg_name in cc.CALLER_SAVED_REGS:
            offset = self.project.arch.registers[reg_name][0]
            out_state.register_written(offset, self.project.arch.registers[reg_name][1], None)

        return out_state


AnalysesHub.register_default("FastConstantPropagation", FastConstantPropagation)
