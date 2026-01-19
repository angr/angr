# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from typing import TYPE_CHECKING, TypeAlias
from collections import defaultdict

import pyvex

from angr.utils.bits import u2s
from angr.block import Block
from angr.analyses.analysis import Analysis
from angr.analyses import AnalysesHub
from angr.knowledge_plugins.functions import Function
from angr.codenode import BlockNode, HookNode, FuncNode
from angr.engines.light import SimEngineNostmtVEX, SimEngineLight
from angr.calling_conventions import SimRegArg, SimStackArg, default_cc
from angr.sim_type import SimTypeBottom, SimTypeFunction
from angr.utils.types import dereference_simtype_by_lib
from .utils import is_sane_register_variable

if TYPE_CHECKING:
    from angr.codenode import CodeNode

# if you're going to change these to an enum, please do some benchmarking
# (kind, subkind, offset)
KIND_SP = 0
KIND_REG = 1
KIND_STACKVAL = 2
KIND_CONST = 3

# for KIND_SP
SUBKIND_SP = 0
SUBKIND_BP = 1

# for KIND_REG, subkind is reg offset
# for KIND_STACKVAL subkind is source stack offset
# offset is const offset from original value, or value for KIND_CONST

FactData: TypeAlias = tuple[int, int, int] | None


class FactCollectorState:
    """
    The abstract state for FactCollector.
    """

    __slots__ = (
        "bp_value",
        "callee_stored_regs",
        "ins_addr",
        "pointer_arg_derefs",
        "reg_reads",
        "reg_reads_count",
        "reg_writes",
        "simple_regs",
        "simple_stack",
        "sp_value",
        "stack_reads",
        "stack_writes",
        "tmps",
    )

    def __init__(self):
        self.tmps: dict[int, FactData] = {}
        self.simple_stack: dict[int, FactData] = {}
        self.simple_regs: dict[int, FactData] = {}
        self.ins_addr = 0

        self.callee_stored_regs: dict[int, int] = {}  # reg offset -> stack offset
        self.reg_reads = {}
        self.reg_reads_count = defaultdict(int)
        self.reg_writes: set[int] = set()
        self.stack_reads = {}
        self.stack_writes: set[int] = set()
        self.pointer_arg_derefs: defaultdict[FactData, int] = defaultdict(int)
        self.sp_value = 0
        self.bp_value = 0

    def register_read(self, offset: int, size_in_bytes: int):
        self.reg_reads_count[offset] += 1
        if offset in self.reg_writes:
            return
        if offset not in self.reg_reads:
            self.reg_reads[offset] = size_in_bytes
        else:
            self.reg_reads[offset] = max(self.reg_reads[offset], size_in_bytes)

    def register_read_undo(self, offset: int) -> None:
        if offset not in self.reg_reads or offset not in self.reg_reads_count:
            return
        self.reg_reads_count[offset] -= 1
        if self.reg_reads_count[offset] == 0:
            self.reg_reads.pop(offset)
            self.reg_reads_count.pop(offset)

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

    def copy(self, with_tmps: bool = True) -> FactCollectorState:
        new_state = FactCollectorState()
        new_state.reg_reads = self.reg_reads.copy()
        new_state.stack_reads = self.stack_reads.copy()
        new_state.stack_writes = self.stack_writes.copy()
        new_state.reg_writes = self.reg_writes.copy()
        new_state.callee_stored_regs = self.callee_stored_regs.copy()
        new_state.sp_value = self.sp_value
        new_state.bp_value = self.bp_value
        new_state.simple_stack = self.simple_stack.copy()
        new_state.simple_regs = self.simple_regs.copy()
        new_state.reg_reads_count = self.reg_reads_count.copy()
        new_state.pointer_arg_derefs = self.pointer_arg_derefs.copy()
        new_state.ins_addr = self.ins_addr
        if with_tmps:
            new_state.tmps = self.tmps.copy()
        return new_state


binop_handler = SimEngineNostmtVEX[FactCollectorState, FactData, FactCollectorState].binop_handler


class SimEngineFactCollectorVEX(
    SimEngineNostmtVEX[FactCollectorState, FactData, None],
    SimEngineLight[FactCollectorState, FactData, Block, None],
):
    """
    The engine for FactCollector.
    """

    def __init__(self, project, bp_as_gpr: bool, track_arg_uses: bool, seen_reg_uses: defaultdict[int, int]):
        self.bp_as_gpr = bp_as_gpr
        self.track_arg_uses = track_arg_uses
        self.seen_reg_uses = seen_reg_uses
        super().__init__(project)

    def _process_block_end(self, stmt_result: list, whitelist: set[int] | None) -> None:
        if self.block.vex.jumpkind == "Ijk_Call" and self.arch.ret_offset is not None:
            self.state.register_written(self.arch.ret_offset, self.arch.bytes)

    def _top(self, bits: int):
        return None

    def _is_top(self, expr) -> bool:
        return expr is None

    def _expr(self, expr):
        r = super()._expr(expr)
        if (
            r is not None
            and r[0] == KIND_REG
            and not (
                isinstance((stmt := self.block.vex.statements[self.stmt_idx]), pyvex.stmt.WrTmp) and stmt.data is expr
            )
        ):
            # don't count wrtmp datas
            self.seen_reg_uses[r[1]] += 1
        return r

    def _handle_conversion(self, from_size: int, to_size: int, signed: bool, operand: pyvex.expr.IRExpr):
        return None

    def _handle_stmt_IMark(self, stmt: pyvex.stmt.IMark):
        self.state.ins_addr = stmt.addr

    def _handle_stmt_Put(self, stmt):
        v = self._expr(stmt.data)
        # there are cases like  VMOV.F32        S0, S0
        # so we need to check if this register write is actually a no-op
        if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
            t = self.state.tmps.get(stmt.data.tmp, None)
            if t is not None and t[0] == KIND_REG and t[1] == stmt.offset:
                same_ins_read = False
                for i in range(self.stmt_idx, -1, -1):
                    if i >= self.block.vex.stmts_used:
                        break
                    prev_stmt = self.block.vex.statements[i]
                    if isinstance(prev_stmt, pyvex.IRStmt.IMark):
                        break
                    if isinstance(prev_stmt, pyvex.IRStmt.WrTmp) and prev_stmt.tmp == stmt.data.tmp:
                        same_ins_read = True
                        break
                if same_ins_read:
                    # we need to revert the read operation as well
                    self.state.register_read_undo(stmt.offset)
                return

        if stmt.offset == self.arch.sp_offset and v is not None and v[0] == KIND_SP:
            self.state.sp_value = v[2]
        elif stmt.offset == self.arch.bp_offset and v is not None and v[1] == KIND_SP:
            self.state.bp_value = v[2]
        else:
            self.state.register_written(stmt.offset, stmt.data.result_size(self.tyenv) // self.arch.byte_width)
            self.state.simple_regs[stmt.offset] = v

    def _handle_stmt_Store(self, stmt: pyvex.IRStmt.Store):
        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)
        if addr is None or not (addr[0] == KIND_SP or (addr[0] in (KIND_REG, KIND_STACKVAL) and self.track_arg_uses)):
            return

        if addr[0] == KIND_SP:
            self.state.stack_written(addr[2], stmt.data.result_size(self.tyenv) // self.arch.byte_width)
            if data is not None and data[0] == KIND_REG and data[2] == 0:
                # push reg; we record the stored register as well as the stack slot offset
                self.state.callee_stored_regs[data[1]] = u2s(addr[2], self.arch.bits)
            self.state.simple_stack[addr[2]] = data
        else:
            self.state.pointer_arg_derefs[addr] |= 2

    def _handle_stmt_WrTmp(self, stmt: pyvex.IRStmt.WrTmp):
        v = self._expr(stmt.data)
        self.state.tmps[stmt.tmp] = v

    def _handle_expr_Const(self, expr: pyvex.IRExpr.Const):
        return (KIND_CONST, 0, expr.con.value)

    def _handle_expr_GSPTR(self, expr):
        return (KIND_CONST, 0, 0)

    def _handle_expr_Get(self, expr):
        if expr.offset == self.arch.sp_offset:
            return (KIND_SP, 0, self.state.sp_value)
        if expr.offset == self.arch.bp_offset and not self.bp_as_gpr:
            return (KIND_SP, 0, self.state.bp_value)
        bits = expr.result_size(self.tyenv)
        self.state.register_read(expr.offset, bits // self.arch.byte_width)
        return self.state.simple_regs.get(expr.offset, (KIND_REG, expr.offset, 0))

    def _handle_expr_GetI(self, expr):
        return None

    def _handle_expr_ITE(self, expr):
        return None

    def _handle_expr_Load(self, expr):
        addr = self._expr(expr.addr)
        if addr is None or not (addr[0] == KIND_SP or (addr[0] in (KIND_REG, KIND_STACKVAL) and self.track_arg_uses)):
            return None

        if addr[0] == KIND_SP:
            self.state.stack_read(addr[2], expr.result_size(self.tyenv) // self.arch.byte_width)
            return self.state.simple_stack.get(addr[2], (KIND_STACKVAL, addr[2], 0))

        self.state.pointer_arg_derefs[addr] |= 1
        return None

    def _handle_expr_RdTmp(self, expr):
        return self.state.tmps.get(expr.tmp, None)

    def _handle_expr_VECRET(self, expr):
        return None

    @binop_handler
    def _handle_binop_Add(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if op0 is None or op1 is None:
            return None
        if op0[0] == KIND_CONST:
            return (op1[0], op1[1], op1[2] + op0[2])
        if op1[0] == KIND_CONST:
            return (op0[0], op0[1], op0[2] + op1[2])
        return None

    @binop_handler
    def _handle_binop_Sub(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if op0 is None or op1 is None:
            return None
        if op0[0] == KIND_CONST:
            return (op1[0], op1[1], op1[2] - op0[2])
        if op1[0] == KIND_CONST:
            return (op0[0], op0[1], op0[2] - op1[2])
        return None

    @binop_handler
    def _handle_binop_And(self, expr):
        op0, op1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if op0 is not None and op0[0] == KIND_SP:
            return op0
        if op1 is not None and op1[0] == KIND_SP:
            return op1
        return None


class FactCollector(Analysis):
    """
    An extremely fast analysis that extracts necessary facts of a function for CallingConventionAnalysis to make
    decision on the calling convention and prototype of a function.
    """

    def __init__(
        self, func: Function, max_depth: int = 100, track_arg_uses: bool = False, track_arg_passthru: bool = False
    ):
        self.function = func
        self._max_depth = max_depth
        self._track_arg_uses = track_arg_uses
        self._track_arg_passthru = track_arg_passthru
        self.callsites: dict[int, tuple[Function, list[FactData]]] = {}

        self.input_args: list[SimRegArg | SimStackArg] | None = None
        self.retval_size: int | None = None
        self.pointer_arg_derefs: defaultdict[FactData, int] = defaultdict(int)
        self.seen_reg_uses: defaultdict[int, int] = defaultdict(int)

        self._analyze()

    def _analyze(self):
        # breadth-first search using function graph, collect registers and stack variables that are written to as well
        # as read from, until max_depth is reached

        end_states = self._analyze_startpoint()
        self._analyze_endpoints_for_retval_size(end_states)
        callee_restored_regs = self._analyze_endpoints_for_restored_regs()
        self._determine_input_args(end_states, callee_restored_regs)

    def _analyze_startpoint(self) -> list[FactCollectorState]:
        func_graph = self.function.transition_graph
        startpoint = self.function.startpoint
        if startpoint is None:
            return []

        bp_as_gpr = self.function.info.get("bp_as_gpr", False)
        engine = SimEngineFactCollectorVEX(self.project, bp_as_gpr, self._track_arg_uses, self.seen_reg_uses)
        init_state = FactCollectorState()
        if self.project.arch.call_pushes_ret:
            init_state.sp_value = self.project.arch.bytes
        init_state.bp_value = init_state.sp_value

        traversed = set()
        queue: list[
            tuple[
                int,
                FactCollectorState,
                CodeNode | BlockNode | HookNode | FuncNode,
                BlockNode | HookNode | FuncNode | None,
            ]
        ] = [(0, init_state, startpoint, None)]
        end_states: list[FactCollectorState] = []
        while queue:
            depth, state, node, retnode = queue.pop(0)
            if isinstance(node, BlockNode) and node in traversed:
                continue
            traversed.add(node)

            if depth > self._max_depth:
                end_states.append(state)
                break

            if isinstance(node, BlockNode) and node.size == 0:
                continue
            func: Function | None = None
            if isinstance(node, (HookNode, FuncNode)):
                # attempt to convert it into a function
                if self.kb.functions.contains_addr(node.addr):
                    func = self.kb.functions.get_by_addr(node.addr)
                else:
                    continue
            if func is not None:
                if func.calling_convention is not None and func.prototype is not None:
                    # consume args and overwrite the return register
                    self._handle_function(state, func)
                if func.returning is False or retnode is None:
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
                if depth + 1 <= self._max_depth:
                    if edge_type == "fake_return":
                        if succ not in traversed:
                            ret_succ = succ
                    elif edge_type == "transition" and not outside:
                        if succ not in traversed:
                            successor_added = True
                            queue.append((depth + 1, state.copy(), succ, None))
                    elif edge_type == "call" or (edge_type == "transition" and outside):
                        # a call or a tail-call
                        # note that it's ok to traverse a called function multiple times
                        if not isinstance(succ, FuncNode) and not self.kb.functions.contains_addr(succ.addr):
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
            if func.calling_convention is not None and func.prototype is not None:
                func_prototype = (
                    dereference_simtype_by_lib(func.prototype, func.prototype_libname)
                    if func.prototype_libname is not None
                    else func.prototype
                )
                arg_locs = func.calling_convention.arg_locs(func_prototype)
            else:
                return
        except (TypeError, ValueError):
            return

        if None in arg_locs:
            return

        if self._track_arg_passthru:
            self.callsites[state.ins_addr] = (func, [])
        for arg_loc in arg_locs:
            val: FactData = None
            for loc in arg_loc.get_footprint():
                if isinstance(loc, SimRegArg):
                    base_offset = self.project.arch.registers[loc.reg_name][0]
                    state.register_read(base_offset + loc.reg_offset, loc.size)
                    self.seen_reg_uses[base_offset] += 1
                    if self._track_arg_passthru:
                        val = state.simple_regs.get(base_offset, (KIND_REG, base_offset, 0))
                elif isinstance(loc, SimStackArg):
                    sp_value = state.sp_value
                    if sp_value is not None:
                        offset = sp_value + loc.stack_offset
                        state.stack_read(offset, loc.size)
                        if self._track_arg_passthru:
                            val = state.simple_stack.get(offset, (KIND_STACKVAL, offset, 0))
            if self._track_arg_passthru:
                self.callsites[state.ins_addr][1].append(val)

        # clobber caller-saved regs
        for reg_name in func.calling_convention.CALLER_SAVED_REGS:
            offset = self.project.arch.registers[reg_name][0]
            state.register_written(offset, self.project.arch.registers[reg_name][1])
            state.simple_regs[offset] = None

    def _analyze_endpoints_for_retval_size(self, end_states):
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
            assert isinstance(endpoint, (BlockNode, HookNode))
            traversed = set()
            queue: list[tuple[int, CodeNode]] = [(0, endpoint)]
            while queue:
                depth, node = queue.pop(0)
                if isinstance(node, BlockNode) and node in traversed:
                    continue
                traversed.add(node)

                if depth > 3:
                    break

                if isinstance(node, BlockNode) and node.size == 0:
                    continue

                func = None
                if isinstance(node, (FuncNode, HookNode)):
                    # attempt to convert it into a function
                    if self.kb.functions.contains_addr(node.addr):
                        func = self.kb.functions.get_by_addr(node.addr)
                    else:
                        continue
                if func is not None:
                    if (
                        func.calling_convention is not None
                        and func.prototype is not None
                        and func.prototype.returnty is not None
                        and not isinstance(func.prototype.returnty, SimTypeBottom)
                    ):
                        # assume the function overwrites the return variable
                        returnty_size = func.prototype.returnty.with_arch(self.project.arch).size
                        assert returnty_size is not None
                        retval_size = returnty_size // self.project.arch.byte_width
                        retval_sizes.append(retval_size)
                    continue

                # if this block ends with a call to a function, we process the function first
                func_succs = [
                    succ
                    for succ in func_graph.successors(node)
                    if isinstance(succ, (FuncNode, HookNode)) or self.kb.functions.contains_addr(succ.addr)
                ]
                if len(func_succs) == 1:
                    succ = func_succs[0]
                    func_succ: Function | None = None
                    if isinstance(succ, (BlockNode, HookNode, FuncNode)) and self.kb.functions.contains_addr(succ.addr):
                        # attempt to convert it into a function
                        func_succ = self.kb.functions.get_by_addr(succ.addr)
                    if func_succ is not None and func_succ.name not in {"_security_check_cookie"}:
                        if (
                            func_succ.calling_convention is not None
                            and func_succ.prototype is not None
                            and func_succ.prototype.returnty is not None
                            and not isinstance(func_succ.prototype.returnty, SimTypeBottom)
                        ):
                            # assume the function overwrites the return variable
                            proto = func_succ.prototype
                            if func_succ.prototype_libname is not None:
                                # we need to deref the prototype in case it uses SimTypeRef internally
                                proto = dereference_simtype_by_lib(proto, func_succ.prototype_libname)

                            assert isinstance(proto, SimTypeFunction) and proto.returnty is not None
                            returnty_size = proto.returnty.with_arch(self.project.arch).size
                            if returnty_size is None:
                                # it may be None if somehow we cannot resolve a SimTypeRef; we fall back to the full
                                # machine word size
                                retval_size = self.project.arch.bytes
                            else:
                                retval_size = returnty_size // self.project.arch.byte_width
                            retval_sizes.append(retval_size)
                            continue
                        if (
                            func_succ.prototype is not None
                            and func_succ.prototype.returnty is not None
                            and isinstance(func_succ.prototype.returnty, SimTypeBottom)
                        ):
                            # callee is void - don't scan VEX for return values since the call
                            # just clobbers rax without returning anything meaningful
                            continue

                block = self.project.factory.block(node.addr, size=node.size)

                # collect tmps so we can trace back through RdTmp
                tmp_definitions = {}
                for stmt in block.vex.statements:
                    if isinstance(stmt, pyvex.IRStmt.WrTmp):
                        tmp_definitions[stmt.tmp] = stmt.data

                # scan the block statements backwards to find writes to the return value register
                retval_size = None
                for stmt in reversed(block.vex.statements):
                    if isinstance(stmt, pyvex.IRStmt.Put):
                        assert block.vex.tyenv is not None
                        size = stmt.data.result_size(block.vex.tyenv) // self.project.arch.byte_width

                        # check if this 64-bit write is actually a sign/zero-extended 32-bit value.
                        if size == 8 and self.project.arch.bits == 64:
                            expr = stmt.data

                            if isinstance(expr, pyvex.IRExpr.RdTmp):
                                expr = tmp_definitions.get(expr.tmp, expr)

                            if isinstance(expr, pyvex.IRExpr.Unop) and expr.op in {"Iop_32Sto64", "Iop_32Uto64"}:
                                size = 4

                        if stmt.offset == retreg_offset:
                            retval_size = max(size, 1)

                if retval_size is not None:
                    retval_sizes.append(retval_size)
                    continue

                for pred, _, data in func_graph.in_edges(node, data=True):
                    edge_type = data.get("type")
                    if pred not in traversed and depth + 1 <= self._max_depth:
                        if edge_type == "call":
                            continue
                        if edge_type in {"transition", "fake_return"}:
                            queue.append((depth + 1, pred))

        # ARM/AArch64: R0/X0 used for both arg0 and return
        if not retval_sizes:
            first_arg_offset = None
            if cc.ARG_REGS:
                arg0_name = cc.ARG_REGS[0]
                if arg0_name in self.project.arch.registers:
                    first_arg_offset = self.project.arch.registers[arg0_name][0]

            if first_arg_offset is not None and first_arg_offset == retreg_offset:
                is_written = False
                for state in end_states:
                    if retreg_offset in state.reg_writes:
                        is_written = True
                        break

                if not is_written:
                    retval_sizes.append(self.project.arch.bytes)

        self.retval_size = max(retval_sizes) if retval_sizes else None

    def _analyze_endpoints_for_restored_regs(self):
        """
        Analyze all endpoints to determine the restored registers.
        """
        func_graph = self.function.transition_graph
        callee_restored_regs = set()

        sp_masks = {
            0xFFFFFFFE,
            0xFFFFFFFC,
            0xFFFFFFF8,
            0xFFFFFFF0,
            0xFFFFFFFF_FFFFFFFE,
            0xFFFFFFFF_FFFFFFFC,
            0xFFFFFFFF_FFFFFFF8,
            0xFFFFFFFF_FFFFFFF0,
        }
        for endpoint in self.function.endpoints:
            assert isinstance(endpoint, (BlockNode, HookNode))
            traversed = set()
            queue: list[tuple[int, CodeNode]] = [(0, endpoint)]
            while queue:
                depth, node = queue.pop(0)
                traversed.add(node)

                if depth > 3:
                    break

                if isinstance(node, BlockNode) and node.size == 0:
                    continue
                if isinstance(node, (HookNode, FuncNode)):
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
                        elif isinstance(stmt.data, pyvex.IRExpr.Binop):
                            if stmt.data.op.startswith("Iop_Add") or stmt.data.op.startswith("Iop_Sub"):
                                if (
                                    isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp)
                                    and tmps.get(stmt.data.args[0].tmp) == "sp"
                                ) or (
                                    isinstance(stmt.data.args[1], pyvex.IRExpr.RdTmp)
                                    and tmps.get(stmt.data.args[1].tmp) == "sp"
                                ):
                                    tmps[stmt.tmp] = "sp"
                            elif stmt.data.op.startswith("Iop_And"):  # noqa: SIM102
                                if (
                                    isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp)
                                    and tmps.get(stmt.data.args[0].tmp) == "sp"
                                    and isinstance(stmt.data.args[1], pyvex.IRExpr.Const)
                                    and stmt.data.args[1].con.value in sp_masks
                                ) or (
                                    isinstance(stmt.data.args[1], pyvex.IRExpr.RdTmp)
                                    and tmps.get(stmt.data.args[1].tmp) == "sp"
                                    and isinstance(stmt.data.args[0], pyvex.IRExpr.Const)
                                    and stmt.data.args[0].con.value in sp_masks
                                ):
                                    tmps[stmt.tmp] = "sp"
                    if isinstance(stmt, pyvex.IRStmt.Put):
                        assert block.vex.tyenv is not None
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

        if self._track_arg_uses:
            for state in end_states:
                for k, v in state.pointer_arg_derefs.items():
                    self.pointer_arg_derefs[k] |= v

        # determine callee-saved registers
        for state in end_states:
            for reg_offset, stack_offset in state.callee_stored_regs.items():
                # we see cases where a register is saved but not restored
                # but should be counted as callee-save. We attempt to detect
                # this by detecting the complete disuse of that argument value.
                if reg_offset in callee_restored_regs or self.seen_reg_uses[reg_offset] < 2:
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
                reg_name = self.project.arch.translate_register_name(offset, size=size)
                arg = SimRegArg(reg_name, size)
                self.input_args.append(arg)

        stack_offset_created = set()
        ret_addr_offset = 0 if not self.project.arch.call_pushes_ret else self.project.arch.bytes
        # handle shadow stack args
        cc_cls = default_cc(
            self.project.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )
        stackarg_sp_buff = cc_cls.STACKARG_SP_BUFF if cc_cls is not None else 0
        for state in end_states:
            for offset, size in state.stack_reads.items():
                offset = u2s(offset, self.project.arch.bits)
                if offset - ret_addr_offset > stackarg_sp_buff:
                    if offset in stack_offset_created or offset in callee_saved_reg_stack_offsets:
                        continue
                    stack_offset_created.add(offset)
                    arg = SimStackArg(offset - ret_addr_offset, size)
                    self.input_args.append(arg)


AnalysesHub.register_default("FunctionFactCollector", FactCollector)
