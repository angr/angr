# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

from collections import defaultdict
from collections.abc import Container, Iterator
from typing import TYPE_CHECKING

import pypcode
import pyvex

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.block import Block
from angr.calling_conventions import SimRegArg, SimStackArg, default_cc_for_project
from angr.codenode import BlockNode, FuncNode, HookNode
from angr.engines.light import SimEngineLight, SimEngineNostmtVEX
from angr.engines.pcode import HeavyPcodeMixin
from angr.engines.pcode.lifter import IRSB as PcodeIRSB
from angr.knowledge_plugins.functions import Function
from angr.sim_type import SimTypeBottom, SimTypeFunction
from angr.utils.bits import u2s
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

type FactData = tuple[int, int, int] | None


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
        self.tmps: dict[int | tuple[int, int], FactData] = {}
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


class SimEngineFactCollectorPcode:
    """Collect the value-flow facts needed for ABI recovery from raw p-code.

    P-code IRSBs intentionally expose no VEX-compatible ``statements``, so the
    VEX light engine iterates nothing on them and returns an empty fact set.
    This engine reads the operations directly instead, interpreting only
    FactCollector's small value domain and leaving everything else at top.
    """

    _CONTROL_FLOW_OPS = {
        pypcode.OpCode.BRANCH,
        pypcode.OpCode.CBRANCH,
        pypcode.OpCode.BRANCHIND,
        pypcode.OpCode.CALL,
        pypcode.OpCode.CALLIND,
        pypcode.OpCode.RETURN,
    }
    _COPY_OPS = {
        pypcode.OpCode.COPY,
        pypcode.OpCode.INT_ZEXT,
        pypcode.OpCode.INT_SEXT,
        pypcode.OpCode.CAST,
    }

    def __init__(
        self,
        project,
        bp_as_gpr: bool,
        track_arg_uses: bool,
        seen_reg_uses: defaultdict[int, int],
    ):
        self.project = project
        self.arch = project.arch
        self.bp_as_gpr = bp_as_gpr
        self.track_arg_uses = track_arg_uses
        self.seen_reg_uses = seen_reg_uses
        self.state: FactCollectorState | None = None

    @staticmethod
    def _tmp_key(varnode) -> tuple[int, int]:
        return int(varnode.offset), int(varnode.size)

    def _value(self, varnode, *, count_register_use: bool = True) -> FactData:
        assert self.state is not None
        space_name = varnode.space.name
        if space_name == "const":
            return KIND_CONST, 0, int(varnode.offset)
        if space_name == "unique":
            return self.state.tmps.get(self._tmp_key(varnode))
        if space_name != "register":
            return None

        offset = int(varnode.offset)
        size = int(varnode.size)
        if offset == self.arch.sp_offset:
            return KIND_SP, SUBKIND_SP, self.state.sp_value
        if offset == self.arch.bp_offset and not self.bp_as_gpr:
            return KIND_SP, SUBKIND_BP, self.state.bp_value

        if count_register_use:
            self.state.register_read(offset, size)
            self.seen_reg_uses[offset] += 1
        return self.state.simple_regs.get(offset, (KIND_REG, offset, 0))

    @staticmethod
    def _varnode_identity(varnode) -> tuple[str, int, int]:
        return varnode.space.name, int(varnode.offset), int(varnode.size)

    @classmethod
    def _zero_idiom_input_registers(cls, operations) -> set[tuple[str, int, int]]:
        """Find register inputs canceled by an x-x zeroing instruction."""

        canceled = set()
        written = {
            cls._varnode_identity(op.output)
            for op in operations
            if op.output is not None and op.output.space.name == "register"
        }
        for op in operations:
            if op.opcode not in {pypcode.OpCode.INT_XOR, pypcode.OpCode.INT_SUB} or len(op.inputs) != 2:
                continue
            left = cls._varnode_identity(op.inputs[0])
            right = cls._varnode_identity(op.inputs[1])
            if left == right and left[0] == "register" and left in written:
                canceled.add(left)
        return canceled

    def _set_value(self, varnode, value: FactData) -> None:
        assert self.state is not None
        space_name = varnode.space.name
        if space_name == "unique":
            self.state.tmps[self._tmp_key(varnode)] = value
            return
        if space_name != "register":
            return

        offset = int(varnode.offset)
        size = int(varnode.size)
        if offset == self.arch.sp_offset and value is not None and value[0] == KIND_SP:
            self.state.sp_value = value[2]
        elif offset == self.arch.bp_offset and not self.bp_as_gpr and value is not None and value[0] == KIND_SP:
            self.state.bp_value = value[2]
        else:
            self.state.register_written(offset, size)
            self.state.simple_regs[offset] = value

    @staticmethod
    def _add(left: FactData, right: FactData) -> FactData:
        if left is None or right is None or left[2] is None or right[2] is None:
            return None
        if left[0] == KIND_CONST and right[0] == KIND_CONST:
            return KIND_CONST, 0, left[2] + right[2]
        if left[0] == KIND_CONST:
            return right[0], right[1], right[2] + left[2]
        if right[0] == KIND_CONST:
            return left[0], left[1], left[2] + right[2]
        return None

    @staticmethod
    def _sub(left: FactData, right: FactData) -> FactData:
        if left is None or right is None or left[2] is None or right[2] is None:
            return None
        if left[0] == KIND_CONST and right[0] == KIND_CONST:
            return KIND_CONST, 0, left[2] - right[2]
        if right[0] == KIND_CONST:
            return left[0], left[1], left[2] - right[2]
        return None

    @staticmethod
    def _and(left: FactData, right: FactData) -> FactData:
        if left is None or right is None or left[2] is None or right[2] is None:
            return None
        if left[0] == KIND_CONST and right[0] == KIND_CONST:
            return KIND_CONST, 0, left[2] & right[2]
        if left[0] == KIND_SP:
            return left
        if right[0] == KIND_SP:
            return right
        return None

    def _load(self, op) -> None:
        assert self.state is not None and op.output is not None
        address = self._value(op.inputs[1])
        value: FactData = None
        if address is not None and address[0] == KIND_SP:
            size = int(op.output.size)
            self.state.stack_read(address[2], size)
            value = self.state.simple_stack.get(address[2], (KIND_STACKVAL, address[2], 0))
        elif address is not None and address[0] in {KIND_REG, KIND_STACKVAL} and self.track_arg_uses:
            self.state.pointer_arg_derefs[address] |= 1
        self._set_value(op.output, value)

    def _store(self, op) -> None:
        assert self.state is not None
        address = self._value(op.inputs[1])
        value = self._value(op.inputs[2])
        if address is None:
            return
        if address[0] == KIND_SP:
            size = int(op.inputs[2].size)
            self.state.stack_written(address[2], size)
            if value is not None and value[0] == KIND_REG and value[2] == 0:
                self.state.callee_stored_regs[value[1]] = u2s(address[2], self.arch.bits)
            self.state.simple_stack[address[2]] = value
        elif address[0] in {KIND_REG, KIND_STACKVAL} and self.track_arg_uses:
            self.state.pointer_arg_derefs[address] |= 2

    def process(self, state: FactCollectorState, *, block: Block) -> None:
        self.state = state
        # Unique-space offsets are reusable scratch locations, not values that
        # survive a basic-block boundary.
        state.tmps.clear()
        irsb = block.vex
        assert isinstance(irsb, PcodeIRSB)
        # FIXME: Shouldn't use protected members of IRSB; see the same access in engines/pcode/emulate.py
        operations = list(irsb._ops)  # pylint:disable=protected-access
        ignored_input_registers: set[tuple[str, int, int]] = set()
        for op_index, op in enumerate(operations):
            opcode = op.opcode
            if opcode == pypcode.OpCode.IMARK:
                if op.inputs:
                    state.ins_addr = int(op.inputs[0].offset)
                instruction_end = next(
                    (
                        index
                        for index in range(op_index + 1, len(operations))
                        if operations[index].opcode == pypcode.OpCode.IMARK
                    ),
                    len(operations),
                )
                ignored_input_registers = self._zero_idiom_input_registers(operations[op_index + 1 : instruction_end])
                continue
            if opcode in self._CONTROL_FLOW_OPS:
                continue
            if opcode == pypcode.OpCode.LOAD:
                self._load(op)
                continue
            if opcode == pypcode.OpCode.STORE:
                self._store(op)
                continue
            if opcode == pypcode.OpCode.CALLOTHER:
                if op.output is not None:
                    self._set_value(op.output, None)
                continue

            values = [
                self._value(
                    varnode,
                    count_register_use=(self._varnode_identity(varnode) not in ignored_input_registers),
                )
                for varnode in op.inputs
            ]
            value: FactData = None
            same_inputs = len(op.inputs) == 2 and self._varnode_identity(op.inputs[0]) == self._varnode_identity(
                op.inputs[1]
            )
            if same_inputs and opcode in {
                pypcode.OpCode.INT_XOR,
                pypcode.OpCode.INT_SUB,
                pypcode.OpCode.INT_LESS,
                pypcode.OpCode.INT_SLESS,
                pypcode.OpCode.INT_NOTEQUAL,
                pypcode.OpCode.INT_SBORROW,
            }:
                value = KIND_CONST, 0, 0
            elif same_inputs and opcode in {
                pypcode.OpCode.INT_EQUAL,
                pypcode.OpCode.INT_LESSEQUAL,
                pypcode.OpCode.INT_SLESSEQUAL,
            }:
                value = KIND_CONST, 0, 1
            elif opcode in self._COPY_OPS and values:
                value = values[0]
            elif opcode == pypcode.OpCode.SUBPIECE and values:
                zero_offset = len(values) == 1 or (
                    values[1] is not None and values[1][0] == KIND_CONST and values[1][2] == 0
                )
                if zero_offset:
                    value = values[0]
            elif opcode == pypcode.OpCode.INT_ADD and len(values) == 2:
                value = self._add(values[0], values[1])
            elif opcode == pypcode.OpCode.INT_SUB and len(values) == 2:
                value = self._sub(values[0], values[1])
            elif opcode == pypcode.OpCode.INT_AND and len(values) == 2:
                value = self._and(values[0], values[1])
            if op.output is not None:
                self._set_value(op.output, value)

        # Mirror SimEngineFactCollectorVEX._process_block_end: after a call the return
        # register holds the callee's result, so it must not read as an incoming argument.
        if irsb.jumpkind == "Ijk_Call" and self.arch.ret_offset is not None:
            state.register_written(self.arch.ret_offset, self.arch.bytes)


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
        self.unused_args: list[SimRegArg] = []
        self.retval_size: int | None = None
        self.pointer_arg_derefs: defaultdict[FactData, int] = defaultdict(int)
        self.extra_pop: int | None = None
        self._seen_reg_uses: defaultdict[int, int] = defaultdict(int)
        self._is_pcode = self._function_uses_pcode()

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
        func_graph = self.function.transition_graph
        startpoint = self.function.startpoint
        if startpoint is None:
            return []

        bp_as_gpr = self.function.info.get("bp_as_gpr", False)
        engine = (
            SimEngineFactCollectorPcode(self.project, bp_as_gpr, self._track_arg_uses, self._seen_reg_uses)
            if self._is_pcode
            else SimEngineFactCollectorVEX(self.project, bp_as_gpr, self._track_arg_uses, self._seen_reg_uses)
        )
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
                    if self.project.arch.call_pushes_ret and not func.is_syscall:
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
                    elif edge_type in {"call", "syscall"} or (edge_type == "transition" and outside):
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
        for reg_name in func.calling_convention.CALLER_SAVED_REGS:
            offset = self.project.arch.registers[reg_name][0]
            state.register_written(offset, self.project.arch.registers[reg_name][1])
            state.simple_regs[offset] = None

    def _function_uses_pcode(self) -> bool:
        return isinstance(self.project.factory.default_engine, HeavyPcodeMixin)

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
        func_graph = self.function.transition_graph
        for _, succ, data in func_graph.out_edges(node, data=True):
            if data.get("type") != "transition" or data.get("outside", False) or not isinstance(succ, BlockNode):
                continue
            succ_block = self.project.factory.block(succ.addr, size=succ.size)
            if succ_block.vex.jumpkind != "Ijk_Call":
                continue
            if not any(
                edge_data.get("type") == "fake_return" for _, _, edge_data in func_graph.out_edges(succ, data=True)
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
        func_graph = self.function.transition_graph
        cc_cls = default_cc_for_project(self.project)
        if cc_cls is None:
            # don't know what the calling convention may be... give up
            return
        cc = cc_cls(self.project.arch)
        if isinstance(cc.RETURN_VAL, SimRegArg):
            retreg_offset = cc.RETURN_VAL.check_offset(self.project.arch)
        else:
            return

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
                        propagated_retval_sizes.append(retval_size)
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
                    if func_succ is not None and func_succ.name != "_security_check_cookie":
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
                            propagated_retval_sizes.append(retval_size)
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
                # block_retval_size stores the size of the first write (in the block) to the return register; this is
                # to account for the common case where the shorter register (e.g., al) is extended to the full register
                # (e.g., rax) before returning.
                block_retval_size = None
                stack_canary_barrier = False
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

                            if isinstance(expr, pyvex.IRExpr.Const) and expr.con.value & 0xFFFF_FFFF_0000_0000 == 0:
                                size = 4

                        if stmt.offset == retreg_offset:
                            if isinstance(node, BlockNode) and self._is_stack_canary_retval_write(
                                node, block, stmt.data, tmp_definitions
                            ):
                                stack_canary_barrier = True
                                break
                            block_retval_size = max(size, 1)
                        if stmt.offset == overflow_retreg_offset:
                            overflow_retval_sizes.append(max(size, 1))

                if block_retval_size is not None:
                    retval_sizes.append(block_retval_size)
                    continue
                if stack_canary_barrier:
                    continue

                for pred, _, data in func_graph.in_edges(node, data=True):
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
        retval_sizes = [retval_size + overflow_retval_size for retval_size in retval_sizes] + propagated_retval_sizes

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

    def _analyze_endpoints_for_extrapop(self) -> int:
        """
        Analyze all endpoints to determine the number of bytes that are popped after popping the return address at the
        end of the function. This information is useful for determining if the function cleans up stack arguments
        before returning.
        """

        if not self.project.arch.call_pushes_ret:
            return 0

        sp_offset = self.project.arch.sp_offset
        sp_diffs = set()  # should all be positive

        for endpoint in self.function.endpoints:
            block = self.project.factory.block(endpoint.addr, size=endpoint.size)
            if not block.instruction_addrs:
                continue
            # ret is the only instruction that can load the return address, and it must be the last instruction of the
            # block. so we simply take a look at sp value diff before and after the last instruction. hopefully this
            # applies for all architectures :)
            last_ins_addr = block.instruction_addrs[-1]
            last_ins_block = self.project.factory.block(last_ins_addr, size=block.addr + block.size - last_ins_addr)
            spt = self.project.analyses.StackPointerTracker(
                None, reg_offsets={self.project.arch.sp_offset}, block=last_ins_block, track_memory=False
            )
            sp_off_after = spt.offset_after(last_ins_addr, sp_offset)
            sp_off_before = spt.offset_before(last_ins_addr, sp_offset)
            if sp_off_after is None or sp_off_before is None:
                continue
            sp_diff = sp_off_after - sp_off_before
            sp_diffs.add(sp_diff - self.project.arch.bytes)

        return 0 if not sp_diffs else max(sp_diffs)

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
        unused_hint_offsets = set()
        for state in end_states:
            for reg_offset, stack_offset in state.callee_stored_regs.items():
                if reg_offset in callee_restored_regs:
                    callee_saved_regs.add(reg_offset)
                    callee_saved_reg_stack_offsets.add(stack_offset)
                elif self._seen_reg_uses[reg_offset] < 2:
                    unused_hint_offsets.add(reg_offset)

        arg_reg_cc = default_cc_for_project(self.project)
        for state in end_states:
            for offset, size in state.reg_reads.items():
                if (
                    offset in reg_offset_created
                    or offset == self.project.arch.bp_offset
                    or not is_sane_register_variable(self.project.arch, offset, size, def_cc=arg_reg_cc)
                    or offset in callee_saved_regs
                ):
                    continue
                reg_offset_created.add(offset)
                reg_name = self.project.arch.translate_register_name(offset, size=size)
                arg = SimRegArg(reg_name, size)
                self.input_args.append(arg)
                if offset in unused_hint_offsets:
                    self.unused_args.append(arg)

        stack_offset_created = set()
        ret_addr_offset = 0 if not self.project.arch.call_pushes_ret else self.project.arch.bytes
        # handle shadow stack args
        cc_cls = default_cc_for_project(self.project)
        stackarg_sp_buff = cc_cls.STACKARG_SP_BUFF if cc_cls is not None else 0
        for state in end_states:
            for offset, size in state.stack_reads.items():
                offset = u2s(offset & ((1 << self.project.arch.bits) - 1), self.project.arch.bits)
                if offset - ret_addr_offset > stackarg_sp_buff:
                    if offset in stack_offset_created or offset in callee_saved_reg_stack_offsets:
                        continue
                    stack_offset_created.add(offset)
                    arg = SimStackArg(offset - ret_addr_offset, size)
                    self.input_args.append(arg)


AnalysesHub.register_default("FunctionFactCollector", FactCollector)
