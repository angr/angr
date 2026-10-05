# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Container, Iterator
from typing import TYPE_CHECKING

import archinfo
import pyvex

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.block import Block
from angr.calling_conventions import SimRegArg, SimStackArg, default_cc_for_project, is_x87_stack_arg
from angr.codenode import BlockNode, FuncNode, HookNode
from angr.engines.light import SimEngineLight, SimEngineNostmtVEX
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFloat, SimTypeFunction
from angr.utils.bits import u2s
from angr.utils.types import dereference_simtype_by_lib

from .utils import (
    fold_fp_lane_reads,
    is_sane_register_variable,
    merge_overlapping_register_spans,
    reg_arg_from_span,
)

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

type FactData = tuple[int, int, int] | None


l = logging.getLogger(__name__)

# (id(CALLER_SAVED_REGS), arch) -> (CALLER_SAVED_REGS, [(offset, size), ...])
_CALLER_SAVED_SPANS: dict[tuple, tuple[list[str], list[tuple[int, int]]]] = {}


def _caller_saved_reg_spans(arch, reg_names: list[str]) -> list[tuple[int, int]]:
    key = (id(reg_names), arch)
    entry = _CALLER_SAVED_SPANS.get(key)
    if entry is None or entry[0] is not reg_names:
        entry = _CALLER_SAVED_SPANS[key] = (reg_names, [arch.registers[reg_name] for reg_name in reg_names])
    return entry[1]


SCALAR_IN_VECTOR_OP_RE = re.compile(r"Iop_[A-Za-z]+(\d+)F0x\d+$")


class FactCollectorState:
    """
    The abstract state for FactCollector.
    """

    __slots__ = (
        "bp_value",
        "callee_stored_regs",
        "ins_addr",
        "pointer_arg_derefs",
        "reg_lane_reads",
        "reg_reads",
        "reg_reads_count",
        "reg_writes",
        "simple_regs",
        "simple_stack",
        "sp_value",
        "stack_reads",
        "stack_reads_fp",
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
        #: widest scalar (<= 8-byte) lane consumed from an FP argument register, directly or through a full-register
        #: copy; it narrows a vector-wide read (movaps xmm6, xmm2) to the width the function actually uses
        self.reg_lane_reads: dict[int, int] = {}
        self.reg_writes: set[int] = set()
        self.stack_reads = {}
        self.stack_reads_fp = set()
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

    def register_entry_read(self, offset: int, size_in_bytes: int):
        """A read of the register's function-entry value, already known to precede any write to it."""
        self.reg_reads_count[offset] += 1
        self.reg_reads[offset] = max(self.reg_reads.get(offset, 0), size_in_bytes)

    def register_lane_read(self, offset: int, size_in_bytes: int):
        if offset in self.reg_writes:
            return
        self.reg_lane_reads[offset] = max(self.reg_lane_reads.get(offset, 0), size_in_bytes)

    def register_read_undo(self, offset: int) -> None:
        if offset not in self.reg_reads or offset not in self.reg_reads_count:
            return
        self.reg_reads_count[offset] -= 1
        if self.reg_reads_count[offset] == 0:
            self.reg_reads.pop(offset)
            self.reg_reads_count.pop(offset)

    def register_written(self, offset: int, size_in_bytes: int):
        self.reg_writes.update(range(offset, offset + size_in_bytes))

    def stack_read(self, offset: int, size_in_bytes: int, fp: bool = False):
        if offset in self.stack_writes:
            return
        if offset not in self.stack_reads:
            self.stack_reads[offset] = size_in_bytes
        else:
            self.stack_reads[offset] = max(self.stack_reads[offset], size_in_bytes)
        if fp:
            self.stack_reads_fp.add(offset)

    def stack_written(self, offset: int, size_int_bytes: int):
        self.stack_writes.update(range(offset, offset + size_int_bytes))

    def copy(self, with_tmps: bool = True) -> FactCollectorState:
        new_state = FactCollectorState()
        new_state.reg_reads = self.reg_reads.copy()
        new_state.stack_reads = self.stack_reads.copy()
        new_state.stack_reads_fp = self.stack_reads_fp.copy()
        new_state.stack_writes = self.stack_writes.copy()
        new_state.reg_writes = self.reg_writes.copy()
        new_state.callee_stored_regs = self.callee_stored_regs.copy()
        new_state.sp_value = self.sp_value
        new_state.bp_value = self.bp_value
        new_state.simple_stack = self.simple_stack.copy()
        new_state.simple_regs = self.simple_regs.copy()
        new_state.reg_reads_count = self.reg_reads_count.copy()
        new_state.reg_lane_reads = self.reg_lane_reads.copy()
        new_state.pointer_arg_derefs = self.pointer_arg_derefs.copy()
        new_state.ins_addr = self.ins_addr
        if with_tmps:
            new_state.tmps = self.tmps.copy()
        return new_state


binop_handler = SimEngineNostmtVEX[FactCollectorState, FactData, FactCollectorState].binop_handler
dirty_handler = SimEngineNostmtVEX[FactCollectorState, FactData, FactCollectorState].dirty_handler


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
        cc_cls = default_cc_for_project(project)
        self._fp_arg_reg_offsets: frozenset[int] = frozenset(
            self.arch.registers[r][0]
            for r in (cc_cls.FP_ARG_REGS if cc_cls is not None else ())
            if r in self.arch.registers
        )
        # address of the instruction whose state-save dirty helper (FXSAVE/XSAVE) has been processed
        self._state_save_ins: int | None = None
        # tmp -> (reg offset, size) for register reads made only to store the register state to memory
        self._state_save_reads: dict[int, tuple[int, int]] = {}

    def process(self, state, *, block=None, whitelist=None, **kwargs):
        self._state_save_ins = None
        self._state_save_reads = {}
        return super().process(state, block=block, whitelist=whitelist, **kwargs)

    def _in_state_save(self) -> bool:
        return self._state_save_ins is not None and self._state_save_ins == self.ins_addr

    @dirty_handler
    def _handle_dirty_amd64g_dirtyhelper_XSAVE(self, stmt: pyvex.stmt.Dirty):
        """FXSAVE/XSAVE: libVEX follows the helper with explicit stores of every vector register, whose reads are not
        argument uses."""
        self._state_save_ins = self.ins_addr

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
                    if (
                        isinstance(prev_stmt, pyvex.IRStmt.WrTmp)
                        and prev_stmt.tmp == stmt.data.tmp
                        and isinstance(prev_stmt.data, pyvex.IRExpr.Get)
                        and prev_stmt.data.offset == stmt.offset
                    ):
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

    @dirty_handler
    def _handle_dirty_x86g_dirtyhelper_loadF80le(self, stmt: pyvex.stmt.Dirty):
        """Treat loadF80le(addr) as a 12-byte FP stack read (long double) for CC fact collection."""
        if len(stmt.args) >= 1:
            addr = self._expr(stmt.args[0])
            if addr is not None and addr[0] == KIND_SP:
                self.state.stack_read(addr[2], 12, fp=True)
            if stmt.tmp not in (-1, 0xFFFFFFFF):
                self.state.tmps[stmt.tmp] = addr

    @dirty_handler
    def _handle_dirty_x86g_dirtyhelper_storeF80le(self, stmt: pyvex.stmt.Dirty):
        """Treat storeF80le(addr, val) as a 12-byte store (long double) for CC fact collection."""
        if len(stmt.args) >= 2:
            addr = self._expr(stmt.args[0])
            if addr is not None and addr[0] == KIND_SP:
                self.state.stack_written(addr[2], 12)

    @dirty_handler
    def _handle_dirty_amd64g_dirtyhelper_loadF80le(self, stmt: pyvex.stmt.Dirty):
        """Treat loadF80le(addr) as a 16-byte FP stack read (long double) for CC fact collection."""
        if len(stmt.args) >= 1:
            addr = self._expr(stmt.args[0])
            if addr is not None and addr[0] == KIND_SP:
                self.state.stack_read(addr[2], 16, fp=True)
            if stmt.tmp not in (-1, 0xFFFFFFFF):
                self.state.tmps[stmt.tmp] = addr

    @dirty_handler
    def _handle_dirty_amd64g_dirtyhelper_storeF80le(self, stmt: pyvex.stmt.Dirty):
        """Treat storeF80le(addr, val) as a 16-byte store (long double) for CC fact collection."""
        if len(stmt.args) >= 2:
            addr = self._expr(stmt.args[0])
            if addr is not None and addr[0] == KIND_SP:
                self.state.stack_written(addr[2], 16)

    def _handle_stmt_Store(self, stmt: pyvex.IRStmt.Store):
        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)
        if self._in_state_save():
            data = None
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
        if isinstance(stmt.data, pyvex.IRExpr.Get) and self._in_state_save():
            # count the read only if a later instruction consumes the value
            offset = stmt.data.offset
            if offset not in self.state.reg_writes:
                self._state_save_reads[stmt.tmp] = (offset, stmt.data.result_size(self.tyenv) // self.arch.byte_width)
            self.state.tmps[stmt.tmp] = self.state.simple_regs.get(offset, (KIND_REG, offset, 0))
            return
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
        size = expr.result_size(self.tyenv) // self.arch.byte_width
        self.state.register_read(expr.offset, size)
        v = self.state.simple_regs.get(expr.offset, (KIND_REG, expr.offset, 0))
        if size <= 8 and v is not None and v[0] == KIND_REG and v[2] == 0 and v[1] in self._fp_arg_reg_offsets:
            # a scalar lane of an FP argument register, read directly or through a register copy
            self.state.register_lane_read(v[1], size)
        return v

    def _handle_expr_GetI(self, expr):
        return None

    def _handle_expr_ITE(self, expr):
        return None

    def _handle_expr_Load(self, expr):
        addr = self._expr(expr.addr)
        if addr is None or not (addr[0] == KIND_SP or (addr[0] in (KIND_REG, KIND_STACKVAL) and self.track_arg_uses)):
            return None

        if addr[0] == KIND_SP:
            fp = expr.ty.startswith("Ity_F")
            self.state.stack_read(addr[2], expr.result_size(self.tyenv) // self.arch.byte_width, fp)
            return self.state.simple_stack.get(addr[2], (KIND_STACKVAL, addr[2], 0))

        self.state.pointer_arg_derefs[addr] |= 1
        return None

    def _handle_expr_RdTmp(self, expr):
        if self._state_save_reads and expr.tmp in self._state_save_reads and not self._in_state_save():
            offset, size = self._state_save_reads.pop(expr.tmp)
            self.state.register_entry_read(offset, size)
        return self.state.tmps.get(expr.tmp, None)

    def _handle_expr_Unop(self, expr: pyvex.expr.Unop):
        self._record_scalar_in_vector_lanes(expr)
        return super()._handle_expr_Unop(expr)

    def _handle_expr_Binop(self, expr: pyvex.expr.Binop):
        self._record_scalar_in_vector_lanes(expr)
        return super()._handle_expr_Binop(expr)

    def _record_scalar_in_vector_lanes(self, expr: pyvex.expr.Unop | pyvex.expr.Binop) -> None:
        """Scalar-in-vector SSE ops (Add32F0x4 = addss, Sqrt64F0x2 = sqrtsd, ...) consume only the low lane of their
        operands; record that lane width for FP argument registers."""
        m = SCALAR_IN_VECTOR_OP_RE.match(expr.op)
        if m is None:
            return
        lane_size = int(m.group(1)) // self.arch.byte_width
        for arg in expr.args:
            if not isinstance(arg, pyvex.expr.RdTmp):
                continue
            v = self.state.tmps.get(arg.tmp)
            if v is not None and v[0] == KIND_REG and v[2] == 0 and v[1] in self._fp_arg_reg_offsets:
                self.state.register_lane_read(v[1], lane_size)

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
        #: callsite -> (callee, values passed to each argument of the callee's prototype, in prototype order)
        self.callsites: dict[int, tuple[Function, list[FactData]]] = {}
        #: callsite -> (callee without a usable prototype, values pushed to the outgoing stack). positions are not
        #: prototype indices.
        self.pushed_arg_callsites: dict[int, tuple[Function, list[FactData]]] = {}

        self.input_args: list[SimRegArg | SimStackArg] | None = None
        self.unused_args: list[SimRegArg] = []
        self.retval_size: int | None = None
        #: True when every endpoint's write to the return register looks like a leftover rather than a return value:
        #: the value written is consumed again in the same block (stored, tested, passed on) after the write. A void
        #: function whose last instruction happens to load into rax looks exactly like a getter from the outside;
        #: this is the one local hint that it is not, and CallingConventionAnalysis only lets call-site evidence
        #: demote a prototype to void when it is set.
        self.retval_incidental: bool = False
        self.pointer_arg_derefs: defaultdict[FactData, int] = defaultdict(int)
        #: Number of bytes the callee pops after the return address on the stack, or None if we cannot determine.
        self.extra_pop: int | None = None
        # Number of bytes popped by code that the function jumps to (e.g., tail calls and split-off continuations)
        self._tailcall_pops: set[int] = set()
        self._seen_reg_uses: defaultdict[int, int] = defaultdict(int)

        self._analyze()

    def _analyze(self):
        # breadth-first search using function graph, collect registers and stack variables that are written to as well
        # as read from, until max_depth is reached

        end_states = self._analyze_startpoint()
        self._analyze_endpoints_for_retval_size(end_states)
        callee_restored_regs = self._analyze_endpoints_for_restored_regs()
        self._determine_input_args(end_states, callee_restored_regs)
        self.extra_pop = self._analyze_endpoints_for_extrapop()

    def _analyze_startpoint(self) -> list[FactCollectorState]:
        startpoint = self.function.startpoint
        if startpoint is None:
            return []

        bp_as_gpr = self.function.info.get("bp_as_gpr", False)
        engine = SimEngineFactCollectorVEX(self.project, bp_as_gpr, self._track_arg_uses, self._seen_reg_uses)
        init_state = FactCollectorState()
        if self.project.arch.call_pushes_ret:
            init_state.sp_value = self.project.arch.bytes
        init_state.bp_value = init_state.sp_value

        traversed = set()
        # the last element marks a tail call
        queue: list[
            tuple[
                int,
                FactCollectorState,
                CodeNode | BlockNode | HookNode | FuncNode,
                CodeNode | BlockNode | HookNode | FuncNode | None,
                bool,
            ]
        ] = [(0, init_state, startpoint, None, False)]
        end_states: list[FactCollectorState] = []
        while queue:
            depth, state, node, retnode, is_tailcall = queue.pop(0)
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
            if is_tailcall and self.kb.functions.contains_addr(node.addr):
                tail_func = self.kb.functions.get_by_addr(node.addr)
                self._tailcall_pops |= self._tailcall_callee_pops(state, tail_func)
                if (
                    func is None
                    and tail_func.calling_convention is not None
                    and tail_func.prototype is not None
                    and tail_func.prototype_source >= PrototypeSource.SIMPROC
                ):
                    # a tail jump targets a BlockNode. Treat it as a call if the target's prototype is trustworthy.
                    # otherwise, analyzing the target's first block is safer than using the inferred arguments.
                    func = tail_func
            if func is not None:
                if func.calling_convention is not None and func.prototype is not None:
                    # consume args and overwrite the return register
                    self._handle_function(state, func)
                elif self._track_arg_passthru and state.sp_value is not None:
                    # no usable prototype: still record which of our own args were pushed to the outgoing call
                    # stack so that the i386 FP arg heuristics can detect individually-passed args
                    pushed_args = []
                    for off in sorted(state.simple_stack):
                        if off >= state.sp_value:
                            val = state.simple_stack[off]
                            if val is not None:
                                pushed_args.append(val)
                    if pushed_args:
                        self.pushed_arg_callsites[state.ins_addr] = (func, pushed_args)
                if func.returning is False or retnode is None:
                    # the function call does not return
                    end_states.append(state)
                else:
                    # enqueue the retnode, but we don't increment the depth
                    new_state = state.copy()
                    if self.project.arch.call_pushes_ret and not func.is_syscall:
                        new_state.sp_value += self.project.arch.bytes
                    queue.append((depth, new_state, retnode, None, False))
                continue

            block = self.project.factory.block(node.addr, size=node.size)
            engine.process(state, block=block)

            successor_added = False
            call_succ, ret_succ = None, None
            call_is_tail = False
            for succ, data in self.function.transition_out_edges(node):
                edge_type = data.get("type")
                outside = data.get("outside", False)
                if depth + 1 <= self._max_depth:
                    if edge_type == "fake_return":
                        if succ not in traversed:
                            ret_succ = succ
                    elif edge_type == "transition" and not outside:
                        if succ not in traversed:
                            successor_added = True
                            queue.append((depth + 1, state.copy(), succ, None, False))
                    elif edge_type in {"call", "syscall"} or (edge_type == "transition" and outside):
                        # a call or a tail-call
                        # note that it's ok to traverse a called function multiple times
                        if not isinstance(succ, FuncNode) and not self.kb.functions.contains_addr(succ.addr):
                            # not sure who we are calling
                            continue
                        call_succ = succ
                        call_is_tail = edge_type == "transition"
            if call_succ is not None:
                successor_added = True
                queue.append((depth + 1, state.copy(), call_succ, ret_succ, call_is_tail))

            if not successor_added:
                end_states.append(state)

        return end_states

    MAX_CONTINUATION_DEPTH = 3

    def _tailcall_callee_pops(self, state: FactCollectorState, func: Function) -> set[int]:
        """
        The numbers of bytes that are popped after the return address on the stack by code that this function jumps
        to. Returns an empty set if we cannot determine.
        """
        if not self.project.arch.call_pushes_ret:
            return set()
        cc = func.calling_convention
        if state.sp_value == self.project.arch.bytes and cc is not None and func.prototype is not None:
            if not cc.CALLEE_CLEANUP:
                return {0}
            proto = (
                dereference_simtype_by_lib(func.prototype, func.prototype_libname)
                if func.prototype_libname is not None
                else func.prototype
            )
            try:
                arg_locs = cc.arg_locs(proto)
            except (TypeError, ValueError):
                return set()
            return {self.project.arch.bytes * sum(1 for arg_loc in arg_locs if isinstance(arg_loc, SimStackArg))}
        return self._continuation_pops(func, self.MAX_CONTINUATION_DEPTH, {self.function.addr})

    def _continuation_pops(self, func: Function, depth: int, visited: set[int]) -> set[int]:
        """
        Bytes popped by the ret instructions of func or the code that func jumps to.
        """
        if func.addr in visited or func.is_simprocedure:
            return set()
        visited.add(func.addr)
        pops = self._ret_pops(func)
        if pops or depth <= 0:
            return pops
        for _, dst, data in func.transition_graph.out_edges(data=True):
            if (
                data.get("type") == "transition"
                and data.get("outside", False)
                and self.kb.functions.contains_addr(dst.addr)
            ):
                pops |= self._continuation_pops(self.kb.functions.get_by_addr(dst.addr), depth - 1, visited)
        return pops

    def _ret_pops(self, func: Function) -> set[int]:
        """
        The numbers of bytes that the ret instructions of func pop after popping the return addr on the stack.
        """
        sp_offset = self.project.arch.sp_offset
        pops = set()
        for endpoint in func.endpoints_with_type["return"]:
            if endpoint.size == 0:
                continue
            block = self.project.factory.block(endpoint.addr, size=endpoint.size)
            # the full lift is usually cached; taking instruction_addrs from it avoids an extra lift
            if block.vex.jumpkind != "Ijk_Ret" or not block.instruction_addrs:
                continue
            # ret is the only instruction that can load the return address, and it must be the last instruction of the
            # block. so we simply take a look at sp value diff before and after the last instruction. hopefully this
            # applies for all architectures :)
            last_ins_addr = block.instruction_addrs[-1]
            last_ins_block = self.project.factory.block(last_ins_addr, size=block.addr + block.size - last_ins_addr)
            sp_diff = self._simple_sp_delta(last_ins_block.vex)
            if sp_diff is None:
                spt = self.project.analyses.StackPointerTracker(
                    None, reg_offsets={sp_offset}, block=last_ins_block, track_memory=False
                )
                sp_off_after = spt.offset_after(last_ins_addr, sp_offset)
                sp_off_before = spt.offset_before(last_ins_addr, sp_offset)
                if sp_off_after is None or sp_off_before is None:
                    continue
                sp_diff = sp_off_after - sp_off_before
            pops.add(sp_diff - self.project.arch.bytes)
        return pops

    def _simple_sp_delta(self, irsb) -> int | None:
        """
        The stack pointer change of a block that only sets sp to sp + a small constant (e.g., ret and ret imm16), or
        None for anything else, which StackPointerTracker then handles.
        """
        if not isinstance(irsb, pyvex.IRSB):
            return None
        sp_offset = self.project.arch.sp_offset
        bits = self.project.arch.bits
        word_ty = f"Ity_I{bits}"
        add_op = f"Iop_Add{bits}"
        sp_tmps: dict[int, int] = {}
        delta = None
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                data = stmt.data
                if isinstance(data, pyvex.IRExpr.Get) and data.offset == sp_offset and data.ty == word_ty:
                    sp_tmps[stmt.tmp] = 0
                elif (
                    isinstance(data, pyvex.IRExpr.Binop)
                    and data.op == add_op
                    and isinstance(data.args[0], pyvex.IRExpr.RdTmp)
                    and data.args[0].tmp in sp_tmps
                    and isinstance(data.args[1], pyvex.IRExpr.Const)
                ):
                    sp_tmps[stmt.tmp] = sp_tmps[data.args[0].tmp] + data.args[1].con.value
            elif isinstance(stmt, pyvex.IRStmt.Put):
                if stmt.offset == sp_offset:
                    if not isinstance(stmt.data, pyvex.IRExpr.RdTmp) or stmt.data.tmp not in sp_tmps:
                        return None
                    delta = sp_tmps[stmt.data.tmp]
                elif (
                    stmt.offset < sp_offset + self.project.arch.bytes
                    and sp_offset < stmt.offset + stmt.data.result_size(irsb.tyenv) // self.project.arch.byte_width
                ):
                    # a write that overlaps sp
                    return None
            elif not isinstance(
                stmt, (pyvex.IRStmt.IMark, pyvex.IRStmt.AbiHint, pyvex.IRStmt.NoOp, pyvex.IRStmt.Store)
            ):
                return None
        if delta is None or delta >= 1 << (bits - 1):
            return None
        return delta

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
                if is_x87_stack_arg(loc):
                    continue
                if isinstance(loc, SimRegArg):
                    base_offset = self.project.arch.registers[loc.reg_name][0]
                    state.register_read(base_offset + loc.reg_offset, loc.size)
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
                if val is not None and val[0] == KIND_REG:
                    self._seen_reg_uses[val[1]] += 1
                self.callsites[state.ins_addr][1].append(val)

        # clobber caller-saved regs
        for offset, size in _caller_saved_reg_spans(self.project.arch, func.calling_convention.CALLER_SAVED_REGS):
            state.register_written(offset, size)
            state.simple_regs[offset] = None

    @staticmethod
    def _resolve_vex_tmp(
        expr: pyvex.IRExpr.IRExpr,
        tmp_definitions: dict[int, pyvex.IRExpr.IRExpr],
        seen_tmps: frozenset[int] = frozenset(),
    ) -> pyvex.IRExpr.IRExpr:
        while isinstance(expr, pyvex.IRExpr.RdTmp) and expr.tmp not in seen_tmps:
            definition = tmp_definitions.get(expr.tmp)
            if definition is None:
                break
            seen_tmps |= {expr.tmp}
            expr = definition
        return expr

    @classmethod
    def _walk_vex_expr(
        cls,
        expr: pyvex.IRExpr.IRExpr,
        tmp_definitions: dict[int, pyvex.IRExpr.IRExpr],
        seen_tmps: frozenset[int] = frozenset(),
    ) -> Iterator[pyvex.IRExpr.IRExpr]:
        if isinstance(expr, pyvex.IRExpr.RdTmp):
            if expr.tmp in seen_tmps:
                return
            definition = tmp_definitions.get(expr.tmp)
            if definition is not None:
                yield from cls._walk_vex_expr(definition, tmp_definitions, seen_tmps | {expr.tmp})
                return

        yield expr
        for child in expr.child_expressions:
            yield from cls._walk_vex_expr(child, tmp_definitions, seen_tmps)

    def _stack_canary_tls_location(self) -> tuple[int, int] | None:
        if self.project.arch.name == "AMD64":
            reg_name, offset = "fs", 0x28
        elif self.project.arch.name == "X86":
            reg_name, offset = "gs", 0x14
        else:
            return None
        return self.project.arch.registers[reg_name][0], offset

    @classmethod
    def _is_tls_canary_load(
        cls,
        expr: pyvex.IRExpr.IRExpr,
        tmp_definitions: dict[int, pyvex.IRExpr.IRExpr],
        tls_reg_offset: int,
        canary_offset: int,
    ) -> bool:
        expr = cls._resolve_vex_tmp(expr, tmp_definitions)
        if not isinstance(expr, pyvex.IRExpr.Load):
            return False
        addr_nodes = tuple(cls._walk_vex_expr(expr.addr, tmp_definitions))
        return any(isinstance(node, pyvex.IRExpr.Get) and node.offset == tls_reg_offset for node in addr_nodes) and any(
            isinstance(node, pyvex.IRExpr.Const) and node.con.value == canary_offset for node in addr_nodes
        )

    @classmethod
    def _is_stack_load(
        cls,
        expr: pyvex.IRExpr.IRExpr,
        tmp_definitions: dict[int, pyvex.IRExpr.IRExpr],
        stack_reg_offsets: Container[int | None],
    ) -> bool:
        expr = cls._resolve_vex_tmp(expr, tmp_definitions)
        if not isinstance(expr, pyvex.IRExpr.Load):
            return False
        return any(
            isinstance(node, pyvex.IRExpr.Get) and node.offset in stack_reg_offsets
            for node in cls._walk_vex_expr(expr.addr, tmp_definitions)
        )

    def _has_terminal_call_successor(self, node: BlockNode) -> bool:
        for succ, data in self.function.transition_out_edges(node):
            if data.get("type") != "transition" or data.get("outside", False) or not isinstance(succ, BlockNode):
                continue
            succ_block = self.project.factory.block(succ.addr, size=succ.size)
            if succ_block.vex.jumpkind != "Ijk_Call":
                continue
            if not any(
                edge_data.get("type") == "fake_return" for _, edge_data in self.function.transition_out_edges(succ)
            ):
                return True
        return False

    def _is_stack_canary_retval_write(
        self,
        node: BlockNode,
        block: Block,
        expr: pyvex.IRExpr.IRExpr,
        tmp_definitions: dict[int, pyvex.IRExpr.IRExpr],
    ) -> bool:
        tls_location = self._stack_canary_tls_location()
        if tls_location is None:
            return False

        expr = self._resolve_vex_tmp(expr, tmp_definitions)
        if not isinstance(expr, pyvex.IRExpr.Binop) or expr.op not in {
            "Iop_Sub32",
            "Iop_Sub64",
            "Iop_Xor32",
            "Iop_Xor64",
        }:
            return False

        tls_reg_offset, canary_offset = tls_location
        stack_reg_offsets = {self.project.arch.sp_offset, self.project.arch.bp_offset}
        op0, op1 = expr.args
        if not (
            (
                self._is_tls_canary_load(op0, tmp_definitions, tls_reg_offset, canary_offset)
                and self._is_stack_load(op1, tmp_definitions, stack_reg_offsets)
            )
            or (
                self._is_tls_canary_load(op1, tmp_definitions, tls_reg_offset, canary_offset)
                and self._is_stack_load(op0, tmp_definitions, stack_reg_offsets)
            )
        ):
            return False

        if not self._has_terminal_call_successor(node):
            return False

        for stmt in block.vex.statements:
            if not isinstance(stmt, pyvex.IRStmt.Exit):
                continue
            guard_nodes = tuple(self._walk_vex_expr(stmt.guard, tmp_definitions))
            if any(
                self._is_tls_canary_load(node, tmp_definitions, tls_reg_offset, canary_offset) for node in guard_nodes
            ) and any(self._is_stack_load(node, tmp_definitions, stack_reg_offsets) for node in guard_nodes):
                return True
        return False

    def _analyze_endpoints_for_retval_size(self, end_states):
        """
        Analyze all endpoints to determine the return value size.
        """
        cc_cls = default_cc_for_project(self.project)
        if cc_cls is None:
            # don't know what the calling convention may be... give up
            return
        cc = cc_cls(self.project.arch)
        if isinstance(cc.RETURN_VAL, SimRegArg):
            retreg_offset = cc.RETURN_VAL.check_offset(self.project.arch)
        else:
            return
        fp_retreg_offset = None
        if isinstance(cc.FP_RETURN_VAL, SimRegArg) and cc.FP_RETURN_VAL.reg_name in self.project.arch.registers:
            fp_retreg_offset = cc.FP_RETURN_VAL.check_offset(self.project.arch)

        # Get the overflow return register offset (rdx on x64 System V, rbx under Go's ABIInternal).
        # This is only used to detect 128-bit return values on Rust and Go binaries, whose ABIs really
        # do return a second word there; elsewhere the overflow register is typically a scratch
        # register, and counting writes to it as part of the return value size incorrectly inflates
        # retval_size and pushes the prototype to void (see
        # CallingConventionAnalysis._guess_retval_type which only maps 9..16 sizes to a type for those
        # binaries).
        overflow_retreg_offset: int | None = None
        if (self.project.is_rust_binary or self.project.is_go_binary) and isinstance(cc.OVERFLOW_RETURN_VAL, SimRegArg):
            overflow_retreg_offset = cc.OVERFLOW_RETURN_VAL.check_offset(self.project.arch)

        retval_sizes = []
        propagated_retval_sizes = []
        overflow_retval_sizes = []
        incidental_flags: list[bool] = []
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
                        and not isinstance(func.prototype.returnty, (SimTypeBottom, SimTypeFloat))
                    ):
                        # assume the function overwrites the return variable
                        returnty_size = func.prototype.returnty.with_arch(self.project.arch).size
                        assert returnty_size is not None
                        retval_size = returnty_size // self.project.arch.byte_width
                        propagated_retval_sizes.append(retval_size)
                        # a callee's result is the return value when the endpoint itself hands off to the callee (a
                        # tail call). Reached through a predecessor, it is `call f; ret`, either `return f()` or
                        # `f(); return;`, and the callers settle which
                        incidental_flags.append(depth > 0)
                    continue

                # if this block ends with a call to a function, we process the function first
                func_succs = [
                    succ
                    for succ, _ in self.function.transition_out_edges(node)
                    if isinstance(succ, (FuncNode, HookNode)) or self.kb.functions.contains_addr(succ.addr)
                ]
                if len(func_succs) == 1:
                    succ = func_succs[0]
                    func_succ: Function | None = None
                    if isinstance(succ, (BlockNode, HookNode, FuncNode)) and self.kb.functions.contains_addr(succ.addr):
                        # attempt to convert it into a function
                        func_succ = self.kb.functions.get_by_addr(succ.addr)
                    if func_succ is not None and func_succ.name != "_security_check_cookie":
                        if (
                            func_succ.calling_convention is not None
                            and func_succ.prototype is not None
                            and func_succ.prototype.returnty is not None
                            and not isinstance(func_succ.prototype.returnty, (SimTypeBottom, SimTypeFloat))
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
                            propagated_retval_sizes.append(retval_size)
                            # a callee's result is the return value when the endpoint itself hands off to the callee (a
                            # tail call). Reached through a predecessor, it is `call f; ret`, either `return f()` or
                            # `f(); return;`, and the callers settle which
                            incidental_flags.append(depth > 0)
                            continue
                        if (
                            func_succ.prototype is not None
                            and func_succ.prototype.returnty is not None
                            and isinstance(func_succ.prototype.returnty, (SimTypeBottom, SimTypeFloat))
                        ):
                            # callee is void or returns in an FP register - don't scan VEX for return values since
                            # the call just clobbers rax without returning anything meaningful
                            continue

                block = self.project.factory.block(node.addr, size=node.size)

                # collect tmps so we can trace back through RdTmp
                tmp_definitions = {}
                for stmt in block.vex.statements:
                    if isinstance(stmt, pyvex.IRStmt.WrTmp):
                        tmp_definitions[stmt.tmp] = stmt.data

                # scan the block statements backwards to find writes to the return value register
                # block_retval_size stores the size of the first write (in the block) to the return register; this is
                # to account for the common case where the shorter register (e.g., al) is extended to the full register
                # (e.g., rax) before returning.
                block_retval_size = None
                retval_stmt_idx = None
                stack_canary_barrier = False
                for stmt_idx, stmt in reversed(list(enumerate(block.vex.statements))):
                    if isinstance(stmt, pyvex.IRStmt.Put):
                        assert block.vex.tyenv is not None
                        size = stmt.data.result_size(block.vex.tyenv) // self.project.arch.byte_width

                        # check if this 64-bit write is actually a sign/zero-extended 32-bit value.
                        if (
                            size == 8
                            and self.project.arch.bits == 64
                            and stmt.data.result_type(block.vex.tyenv) == "Ity_I64"
                        ):
                            expr = stmt.data

                            if isinstance(expr, pyvex.IRExpr.RdTmp):
                                expr = tmp_definitions.get(expr.tmp, expr)

                            if isinstance(expr, pyvex.IRExpr.Unop) and expr.op in {"Iop_32Sto64", "Iop_32Uto64"}:
                                size = 4

                            if isinstance(expr, pyvex.IRExpr.Const) and expr.con.value & 0xFFFF_FFFF_0000_0000 == 0:
                                size = 4

                        if stmt.offset == retreg_offset:
                            if isinstance(node, BlockNode) and self._is_stack_canary_retval_write(
                                node, block, stmt.data, tmp_definitions
                            ):
                                stack_canary_barrier = True
                                break
                            block_retval_size = max(size, 1)
                            retval_stmt_idx = stmt_idx
                        if stmt.offset == overflow_retreg_offset:
                            overflow_retval_sizes.append(max(size, 1))

                if block_retval_size is not None:
                    retval_sizes.append(block_retval_size)
                    assert retval_stmt_idx is not None
                    # a block that ends in a call cannot vouch for a return value: whatever it put in the return
                    # register is an argument or scratch that the callee clobbers before the function returns
                    incidental_flags.append(
                        bool(func_succs)
                        or self._retval_write_is_incidental(
                            block.vex, retval_stmt_idx, retreg_offset, block_retval_size, fp_retreg_offset
                        )
                    )
                    l.debug(
                        "retval: endpoint %#x, block %#x writes the return register (%d bytes), incidental=%s",
                        endpoint.addr,
                        node.addr,
                        block_retval_size,
                        incidental_flags[-1],
                    )
                    continue
                if stack_canary_barrier:
                    continue

                for pred, data in self.function.transition_in_edges(node):
                    edge_type = data.get("type")
                    if pred not in traversed and depth + 1 <= self._max_depth:
                        if edge_type in {"call", "syscall"}:
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

        overflow_retval_size = max(overflow_retval_sizes) if overflow_retval_sizes else 0
        if (
            retval_sizes
            and overflow_retreg_offset is None
            and isinstance(self.project.arch, archinfo.ArchX86)
            and isinstance(cc.OVERFLOW_RETURN_VAL, SimRegArg)
        ):
            # 64-bit integers are returned in edx:eax. edx is scratch, so require both sides to agree: the callee
            # defines edx on every path to ret, and a caller reads it after the call
            edx_offset = cc.OVERFLOW_RETURN_VAL.check_offset(self.project.arch)
            if self._callers_read_reg_after_call(edx_offset) and self._reg_defined_at_all_rets(edx_offset):
                overflow_retval_size = self.project.arch.bytes
        self.retval_incidental = bool(incidental_flags) and all(incidental_flags)
        retval_sizes = [retval_size + overflow_retval_size for retval_size in retval_sizes] + propagated_retval_sizes

        self.retval_size = max(retval_sizes) if retval_sizes else None

    def _ret64_callee(self, func: Function, call_block_addr: int) -> bool:
        """Whether the call at the end of ``call_block_addr`` in ``func`` returns a value wider than a word."""
        target = func.get_call_target(call_block_addr)
        if target is None or not self.kb.functions.contains_addr(target):
            return False
        callee = self.kb.functions.get_by_addr(target)
        if callee.prototype is None or callee.prototype.returnty is None:
            return False
        returnty = callee.prototype.returnty
        if isinstance(returnty, (SimTypeBottom, SimTypeFloat)):
            return False
        size = returnty.with_arch(self.project.arch).size
        return size is not None and size > self.project.arch.bits

    def _block_writes_reg(self, addr: int, size: int, reg_offset: int) -> bool:
        block = self.project.factory.block(addr, size=size)
        reg_size = self.project.arch.bytes
        assert block.vex.tyenv is not None
        for stmt in block.vex.statements:
            if (
                isinstance(stmt, pyvex.IRStmt.Put)
                and stmt.offset == reg_offset
                and stmt.data.result_size(block.vex.tyenv) == reg_size * self.project.arch.byte_width
            ):
                return True
        return False

    def _reg_defined_at_all_rets(self, reg_offset: int) -> bool:
        """Must-define analysis: is the register fully written on every path from the entry to every ret?"""
        func = self.function
        ret_sites = [n for n in func.ret_sites if isinstance(n, BlockNode)]
        if not ret_sites or func.startpoint is None:
            return False
        start_addr = func.startpoint.addr
        graph = func.graph
        writes: dict[BlockNode, bool] = {}
        for node in graph:
            if isinstance(node, BlockNode) and node.size > 0:
                writes[node] = self._block_writes_reg(node.addr, node.size, reg_offset)
        out: dict[BlockNode, bool] = dict.fromkeys(writes, True)

        def in_value(node: BlockNode) -> bool:
            if node.addr == start_addr:
                return False
            preds = list(graph.in_edges(node, data=True))
            if not preds:
                return False
            for pred, _, data in preds:
                if not isinstance(pred, BlockNode) or pred not in out:
                    return False
                if data.get("type") == "fake_return":
                    if not self._ret64_callee(func, pred.addr):
                        return False
                elif not out[pred]:
                    return False
            return True

        # optimistic start; flip nodes to False until nothing changes
        worklist = list(out)
        while worklist:
            node = worklist.pop()
            if not out[node] or writes[node] or in_value(node):
                continue
            out[node] = False
            worklist.extend(succ for succ in graph.successors(node) if out.get(succ))
        return all(out.get(n, False) for n in ret_sites)

    MAX_CALLER_SITES = 16

    def _callers_read_reg_after_call(self, reg_offset: int) -> bool:
        """Does any caller read the register after a call to this function before redefining it? Callers of stubs
        that tail-jump here count."""
        funcs = self.kb.functions
        seen_targets: set[int] = set()
        worklist: list[tuple[int, int]] = [(self.function.addr, 0)]
        sites = 0
        while worklist:
            target, depth = worklist.pop(0)
            if target in seen_targets:
                continue
            seen_targets.add(target)
            for caller_addr in list(funcs.callgraph.predecessors(target)):
                if not funcs.contains_addr(caller_addr):
                    continue
                caller = funcs.get_by_addr(caller_addr)
                if caller_addr != target:
                    for callsite in caller.get_call_sites():
                        if caller.get_call_target(callsite) != target:
                            continue
                        ret_addr = caller.get_call_return(callsite)
                        if ret_addr is None:
                            continue
                        sites += 1
                        if self._reg_read_after(caller, ret_addr, reg_offset):
                            return True
                        if sites >= self.MAX_CALLER_SITES:
                            return False
                if depth == 0:
                    tg = caller.transition_graph
                    for site in caller.jumpout_sites:
                        # an actual jump; falling through (e.g., past a call to a noreturn function) does not count
                        if not isinstance(site, BlockNode) or site.size == 0:
                            continue
                        site_insns = self.project.factory.block(site.addr, size=site.size).capstone.insns
                        if not site_insns or not site_insns[-1].mnemonic.startswith("j"):
                            continue
                        if any(
                            succ.addr == target and data.get("outside", False)
                            for _, succ, data in tg.out_edges(site, data=True)
                        ):
                            worklist.append((caller_addr, depth + 1))
                            break
        return False

    def _reg_read_after(self, func: Function, addr: int, reg_offset: int, max_blocks: int = 4) -> bool:
        """Is the register read after the call returning to ``addr`` before being written? A caller that also reads
        another clobbered register (ecx) is capturing the register state, not consuming a return value."""
        arch = self.project.arch
        reg_size = arch.bytes
        lo_offset = arch.ret_offset
        lo_name = arch.register_names[lo_offset]
        cc_cls = default_cc_for_project(self.project)
        scratch_names = (
            [r for r in cc_cls.CALLER_SAVED_REGS if r in arch.registers and arch.registers[r][0] != lo_offset]
            if cc_cls is not None
            else []
        )
        # offset -> name; reg_offset is among them
        tracked = {arch.registers[r][0]: r for r in scratch_names}
        tracked[reg_offset] = arch.register_names[reg_offset]
        start = func.get_node(addr)
        if start is None:
            return False
        graph = func.transition_graph
        # (node, registers written so far on this path)
        queue: list[tuple[BlockNode, frozenset[int]]] = [(start, frozenset())]
        visited: set[BlockNode] = set()
        while queue and len(visited) < max_blocks:
            node, written = queue.pop(0)
            if node in visited or node.size == 0:
                continue
            visited.add(node)
            block = self.project.factory.block(node.addr, size=node.size)
            # reads that do not consume a value: `sbb edx, edx` and friends, bit scans that VEX models as keeping the
            # destination, and pushes used to pad the stack (unless pushing the high half of a register pair, as in
            # `push edx; push eax`)
            insns = block.capstone.insns
            ignored = set()
            for i, insn in enumerate(insns):
                for name in tracked.values():
                    if (insn.mnemonic in {"sbb", "sub", "xor"} and insn.op_str == f"{name}, {name}") or (
                        insn.mnemonic in {"bsf", "bsr", "tzcnt", "lzcnt"} and insn.op_str.startswith(f"{name},")
                    ):
                        ignored.add(insn.address)
                    elif insn.mnemonic == "push" and insn.op_str == name:
                        nxt = insns[i + 1] if i + 1 < len(insns) else None
                        if (
                            name != tracked[reg_offset]
                            or nxt is None
                            or nxt.mnemonic != "push"
                            or nxt.op_str != lo_name
                        ):
                            ignored.add(insn.address)
            assert block.vex.tyenv is not None
            written_now = set(written)
            reg_read = scratch_read = False
            ins_addr = None
            for stmt in block.vex.statements:
                if isinstance(stmt, pyvex.IRStmt.IMark):
                    ins_addr = stmt.addr
                    continue
                if ins_addr not in ignored:
                    for expr in stmt.expressions:
                        if not isinstance(expr, pyvex.IRExpr.Get):
                            continue
                        for off in tracked:
                            if (
                                off not in written_now
                                and expr.offset < off + reg_size
                                and off < expr.offset + (expr.result_size(block.vex.tyenv) // arch.byte_width)
                            ):
                                if off == reg_offset:
                                    reg_read = True
                                else:
                                    scratch_read = True
                # any write, partial ones included (`sete dl; or eax, edx`), ends tracking of that register
                if isinstance(stmt, pyvex.IRStmt.Put):
                    for off in tracked:
                        if off <= stmt.offset < off + reg_size:
                            written_now.add(off)
            if scratch_read:
                return False
            if reg_read:
                return True
            if reg_offset in written_now or func.get_call_target(node.addr) is not None or node not in graph:
                continue
            for _, succ, data in graph.out_edges(node, data=True):
                if (
                    isinstance(succ, BlockNode)
                    and succ not in visited
                    and data.get("type") == "transition"
                    and not data.get("outside", False)
                ):
                    queue.append((succ, frozenset(written_now)))
        return False

    def _retval_write_is_incidental(
        self, irsb, put_idx: int, retreg_offset: int, retreg_size: int, fp_retreg_offset: int | None
    ) -> bool:
        """Is the write to the return register at ``put_idx`` a leftover rather than a return value?

        It is when the value written is used again after the write, in the same block: stored to memory, put in
        another register, tested by a conditional exit. ``mov eax, [rdi]; ...; mov [rsi], eax; ret`` writes rax
        first and returns it last, but the value's job was the store. VEX folds the later register read into a
        reuse of the very tmp that was put into the register, so this follows tmps and what derives from them,
        and treats an explicit re-read of the register the same way.

        One consumer is exempt: the floating-point return register. ``fabs`` masks the sign bit in rax and moves
        the result back to xmm0; that value is the return value, it just travelled through rax.
        """
        put = irsb.statements[put_idx]
        derived: set[int] = set()
        if isinstance(put.data, pyvex.IRExpr.RdTmp):
            derived.add(put.data.tmp)

        def reads_retval(stmt) -> bool:
            for expr in stmt.expressions:
                if isinstance(expr, pyvex.IRExpr.RdTmp) and expr.tmp in derived:
                    return True
                if (
                    isinstance(expr, pyvex.IRExpr.Get)
                    and expr.offset < retreg_offset + retreg_size
                    and expr.offset + expr.result_size(irsb.tyenv) // self.project.arch.byte_width > retreg_offset
                ):
                    return True
            return False

        for stmt in irsb.statements[put_idx + 1 :]:
            if isinstance(stmt, (pyvex.IRStmt.IMark, pyvex.IRStmt.AbiHint, pyvex.IRStmt.NoOp)):
                continue
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                if reads_retval(stmt):
                    derived.add(stmt.tmp)
                continue
            # a Put of the next instruction address is a constant and reads nothing; a Put of a derived tmp into the
            # instruction pointer is `jmp rax`, and consumes the value like any other use
            if reads_retval(stmt):
                return not (isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == fp_retreg_offset)
        return False

    def _analyze_endpoints_for_restored_regs(self):
        """
        Analyze all endpoints to determine the restored registers.
        """
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
        # the registers a block restores do not depend on the endpoint we walk back from
        restored_by_block: dict[CodeNode, set[int]] = {}
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

                regs = restored_by_block.get(node)
                if regs is None:
                    regs = restored_by_block[node] = self._block_restored_regs(node, sp_masks)
                callee_restored_regs |= regs

                for pred, data in self.function.transition_in_edges(node):
                    edge_type = data.get("type")
                    if pred not in traversed and depth + 1 <= self._max_depth and edge_type == "transition":
                        queue.append((depth + 1, pred))

        # remove offsets of registers that are caller-saved (including return value registers and argument registers)
        # from callee_restored_regs, since these registers are not callee-saved per the ABI
        caller_saved_offsets = set()
        cc_cls = default_cc_for_project(self.project)
        if cc_cls is not None:
            cc = cc_cls(self.project.arch)
            if isinstance(cc.RETURN_VAL, SimRegArg):
                retreg_offset = cc.RETURN_VAL.check_offset(self.project.arch)
                caller_saved_offsets.add(retreg_offset)
            if isinstance(cc.OVERFLOW_RETURN_VAL, SimRegArg):
                retreg_offset = cc.OVERFLOW_RETURN_VAL.check_offset(self.project.arch)
                caller_saved_offsets.add(retreg_offset)
            if isinstance(cc.FP_RETURN_VAL, SimRegArg):
                try:
                    retreg_offset = cc.FP_RETURN_VAL.check_offset(self.project.arch)
                    caller_saved_offsets.add(retreg_offset)
                except KeyError:
                    # register name does not exist
                    pass
            for reg_name in cc.CALLER_SAVED_REGS:
                if reg_name in self.project.arch.registers:
                    caller_saved_offsets.add(self.project.arch.registers[reg_name][0])

        return callee_restored_regs.difference(caller_saved_offsets)

    def _block_restored_regs(self, node: CodeNode, sp_masks: set[int]) -> set[int]:
        """Registers that a block restores from the stack."""
        regs = set()
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
                    regs.add(stmt.offset)
        return regs

    def _analyze_endpoints_for_extrapop(self) -> int | None:
        """
        Analyze all endpoints to determine the number of bytes that are popped after popping the return address at the
        end of the function. This information is useful for determining if the function cleans up stack arguments
        before returning.

        Only use popped bytes by the following:
        - ret instructions (including those of split-off continuations)
        - tail calls to functions with known caller/callee cleanup configuration.
        Returns None if we cannot determine the number of popped bytes.
        """

        if not self.project.arch.call_pushes_ret:
            return 0
        sp_diffs = self._ret_pops(self.function) | self._tailcall_pops  # should all be positive
        return max(sp_diffs) if sp_diffs else None

    def _determine_input_args(self, end_states: list[FactCollectorState], callee_restored_regs: set[int]) -> None:
        self.input_args = []
        callee_saved_regs = set()
        callee_saved_reg_stack_offsets = set()

        if self._track_arg_uses:
            for state in end_states:
                for k, v in state.pointer_arg_derefs.items():
                    self.pointer_arg_derefs[k] |= v

        # determine callee-saved registers
        unused_hint_offsets = set()
        for state in end_states:
            for reg_offset, stack_offset in state.callee_stored_regs.items():
                if reg_offset in callee_restored_regs:
                    callee_saved_regs.add(reg_offset)
                    callee_saved_reg_stack_offsets.add(stack_offset)
                elif self._seen_reg_uses[reg_offset] < 2:
                    unused_hint_offsets.add(reg_offset)

        arg_reg_cc = default_cc_for_project(self.project)
        reg_reads: dict[int, int] = {}
        reg_lane_reads: dict[int, int] = {}
        for state in end_states:
            for offset, size in state.reg_reads.items():
                if (
                    offset == self.project.arch.bp_offset
                    or not is_sane_register_variable(self.project.arch, offset, size, def_cc=arg_reg_cc)
                    or offset in callee_saved_regs
                ):
                    continue
                reg_reads[offset] = max(reg_reads.get(offset, 0), size)
            for offset, size in state.reg_lane_reads.items():
                reg_lane_reads[offset] = max(reg_lane_reads.get(offset, 0), size)
        reg_reads = fold_fp_lane_reads(self.project.arch, reg_reads, arg_reg_cc)
        # reads of overlapping sub-registers (e.g., ch and cx) describe one argument
        for offset, size in merge_overlapping_register_spans(self.project.arch, reg_reads.items()):
            arg = reg_arg_from_span(self.project.arch, offset, size)
            if size > 8 and offset in reg_lane_reads:
                # vector-wide read of an FP argument register; the scalar lane width is the argument width
                arg = SimRegArg(arg.reg_name, reg_lane_reads[offset])
            self.input_args.append(arg)
            if offset in unused_hint_offsets:
                self.unused_args.append(arg)

        stack_offset_created = set()
        ret_addr_offset = 0 if not self.project.arch.call_pushes_ret else self.project.arch.bytes
        # handle shadow stack args
        cc_cls = default_cc_for_project(self.project)
        # the first stack argument sits right after the return address and the reserved area (160(%r15) on s390x)
        first_stackarg = (cc_cls.STACKARG_SP_DIFF + cc_cls.STACKARG_SP_BUFF) if cc_cls is not None else 0
        first_stackarg = max(first_stackarg, 1)
        for state in end_states:
            for offset, size in state.stack_reads.items():
                offset = u2s(offset & ((1 << self.project.arch.bits) - 1), self.project.arch.bits)
                if offset - ret_addr_offset >= first_stackarg:
                    if offset in stack_offset_created or offset in callee_saved_reg_stack_offsets:
                        continue
                    stack_offset_created.add(offset)
                    is_fp = offset in state.stack_reads_fp
                    arg = SimStackArg(offset - ret_addr_offset, size, is_fp)
                    self.input_args.append(arg)


AnalysesHub.register_default("FunctionFactCollector", FactCollector)
