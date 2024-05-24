# pylint:disable=abstract-method,ungrouped-imports

from typing import Optional, TYPE_CHECKING
import re
import logging
from collections import defaultdict

import pyvex

from angr.analyses import ForwardAnalysis, visitors
from ..utils.constants import is_alignment_mask
from ..analyses import AnalysesHub
from ..knowledge_plugins import Function
from ..block import BlockNode
from ..errors import SimTranslationError
from .analysis import Analysis

try:
    import pypcode
    from angr.engines import pcode
except ImportError:
    pypcode = None

if TYPE_CHECKING:
    from angr.block import Block

_l = logging.getLogger(name=__name__)


class BottomType:
    """
    The bottom value for register values.
    """

    def __repr__(self):
        return "<Bottom>"


TOP = None
BOTTOM = BottomType()


class Constant:
    """
    Represents a constant value.
    """

    __slots__ = ("val",)

    def __init__(self, val):
        self.val = val

    def __eq__(self, other):
        if type(other) is Constant or isinstance(other, Constant):
            return self.val == other.val
        return False

    def __hash__(self):
        return hash((Constant, self.val))

    def __repr__(self):
        return repr(self.val)

    def __add__(self, other):
        if type(self) is type(other):
            return Constant(self.val + other.val)
        else:
            return other + self

    def __sub__(self, other):
        if type(self) is type(other):
            return Constant(self.val - other.val)
        else:
            raise CouldNotResolveException


class Register:
    """
    Represent a register.
    """

    __slots__ = ("offset", "bitlen")

    def __init__(self, offset, bitlen):
        self.offset = offset
        self.bitlen = bitlen

    def __hash__(self):
        return hash((Register, self.offset))

    def __eq__(self, other):
        if type(other) is Register or isinstance(other, Register):
            return self.offset == other.offset
        return False

    def __repr__(self):
        return str(self.offset)


class OffsetVal:
    """
    Represent a value with an offset added.
    """

    __slots__ = (
        "_reg",
        "_offset",
    )

    def __init__(self, reg, offset):
        self._reg = reg
        self._offset = offset

    @property
    def reg(self):
        return self._reg

    @property
    def offset(self):
        return self._offset

    def __add__(self, other):
        if type(other) is Constant:
            return OffsetVal(self._reg, (self._offset + other.val) & (2**self.reg.bitlen - 1))
        else:
            raise CouldNotResolveException

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if type(other) is Constant:
            return OffsetVal(self._reg, self._offset - other.val & (2**self.reg.bitlen - 1))
        else:
            raise CouldNotResolveException

    def __rsub__(self, other):
        raise CouldNotResolveException

    def __eq__(self, other):
        if type(other) is OffsetVal or isinstance(other, OffsetVal):
            return self.reg == other.reg and self.offset == other.offset
        return False

    def __hash__(self):
        return hash((type(self), self._reg, self._offset))

    def __repr__(self):
        return f"reg({self.reg}){(self.offset - 2**self.reg.bitlen) if self.offset != 0 else 0:+}"


class Eq:
    """
    Represent an equivalence condition.
    """

    __slots__ = ("val0", "val1")

    def __init__(self, val0, val1):
        self.val0 = val0
        self.val1 = val1

    def __hash__(self):
        return hash((type(self), self.val0, self.val1))


class FrozenStackPointerTrackerState:
    """
    Abstract state for StackPointerTracker analysis with registers and memory values being in frozensets.
    """

    __slots__ = "regs", "memory", "is_tracking_memory"

    def __init__(self, regs, memory, is_tracking_memory):
        self.regs = regs
        self.memory = memory
        self.is_tracking_memory = is_tracking_memory

    def unfreeze(self):
        return StackPointerTrackerState(dict(self.regs), dict(self.memory), self.is_tracking_memory)

    def __hash__(self):
        if self.is_tracking_memory:
            return hash((FrozenStackPointerTrackerState, self.regs, self.memory, self.is_tracking_memory))
        else:
            return hash((FrozenStackPointerTrackerState, self.regs, self.is_tracking_memory))

    def merge(self, other):
        return self.unfreeze().merge(other.unfreeze()).freeze()

    def __eq__(self, other):
        if type(other) is FrozenStackPointerTrackerState or isinstance(other, FrozenStackPointerTrackerState):
            cond1 = self.regs == other.regs and self.is_tracking_memory == other.is_tracking_memory
            if self.is_tracking_memory:
                cond1 &= self.memory == other.memory
            return cond1
        return False


class StackPointerTrackerState:
    """
    Abstract state for StackPointerTracker analysis.
    """

    __slots__ = "regs", "memory", "is_tracking_memory"

    def __init__(self, regs, memory, is_tracking_memory):
        self.regs = regs
        if is_tracking_memory:
            self.memory = memory
        else:
            self.memory = {}
        self.is_tracking_memory = is_tracking_memory

    def give_up_on_memory_tracking(self):
        self.memory = {}
        self.is_tracking_memory = False

    def store(self, addr, val):
        # strong update
        if self.is_tracking_memory and val is not None and addr is not None:
            self.memory[addr] = val

    def load(self, addr):
        if not self.is_tracking_memory:
            return TOP
        try:
            val = self.memory[addr]
            if val is not TOP:
                return val
        except KeyError:
            pass
        raise CouldNotResolveException

    def get(self, reg):
        try:
            val = self.regs[reg]
            if val is not TOP:
                return val
        except KeyError:
            pass
        raise CouldNotResolveException

    def put(self, reg, val):
        # strong update, but we only update values for registers that are already in self.regs and ignore all other
        # registers. obviously, self.regs should be initialized with registers that should be considered during
        # tracking,
        if reg in self.regs:
            self.regs[reg] = val

    def copy(self):
        return StackPointerTrackerState(self.regs.copy(), self.memory.copy(), self.is_tracking_memory)

    def freeze(self):
        return FrozenStackPointerTrackerState(
            frozenset(self.regs.items()), frozenset(self.memory.items()), self.is_tracking_memory
        )

    def __eq__(self, other):
        if type(other) is StackPointerTrackerState or isinstance(other, StackPointerTrackerState):
            cond1 = self.regs == other.regs and self.is_tracking_memory == other.is_tracking_memory
            if self.is_tracking_memory:
                cond1 &= self.memory == other.memory
            return cond1
        return False

    def __hash__(self):
        if self.is_tracking_memory:
            return hash((StackPointerTrackerState, self.regs, self.memory, self.is_tracking_memory))
        else:
            return hash((StackPointerTrackerState, self.regs, self.is_tracking_memory))

    def merge(self, other):
        return StackPointerTrackerState(
            regs=_dict_merge(self.regs, other.regs),
            memory=_dict_merge(self.memory, other.memory),
            is_tracking_memory=self.is_tracking_memory and other.is_tracking_memory,
        )


def _dict_merge(d1, d2):
    all_keys = set(d1.keys()) | set(d2.keys())
    merged = {}
    for k in all_keys:
        if k not in d1 or d1[k] is TOP:
            merged[k] = TOP
        elif k not in d2 or d2[k] is TOP:
            merged[k] = TOP
        elif d1[k] is BOTTOM:
            merged[k] = d2[k]
        elif d2[k] is BOTTOM:
            merged[k] = d1[k]
        elif d1[k] == d2[k]:
            merged[k] = d1[k]
        else:  # d1[k] != d2[k]
            merged[k] = TOP
    return merged


class CouldNotResolveException(Exception):
    """
    An exception used in StackPointerTracker analysis to represent internal resolving failures.
    """


IROP_CONVERT_REGEX = re.compile(r"^Iop_(\d+)(U{0,1})to(\d+)(U{0,1})$")


class StackPointerTracker(Analysis, ForwardAnalysis):
    """
    Track the offset of stack pointer at the end of each basic block of a function.
    """

    def __init__(
        self,
        func: Function | None,
        reg_offsets: set[int],
        block: Optional["Block"] = None,
        track_memory=True,
        cross_insn_opt=True,
        initial_reg_values=None,
    ):
        if func is not None:
            if not func.normalized:
                # Make a copy before normalizing the function
                func = func.copy()
                func.normalize()
            graph_visitor = visitors.FunctionGraphVisitor(func)
        elif block is not None:
            graph_visitor = visitors.SingleNodeGraphVisitor(block)
        else:
            raise ValueError("StackPointerTracker must work on either a function or a single block.")

        super().__init__(order_jobs=False, allow_merging=True, allow_widening=track_memory, graph_visitor=graph_visitor)

        self.track_mem = track_memory
        self._func = func
        self.reg_offsets = reg_offsets
        self.states = {}
        self._blocks = {}
        self._reg_value_at_block_start = defaultdict(dict)
        self.cross_insn_opt = cross_insn_opt

        if initial_reg_values:
            self._reg_value_at_block_start[func.addr if func is not None else block.addr] = initial_reg_values

        _l.debug("Running on function %r", self._func)
        self._analyze()

    def _state_for(self, addr, pre_or_post):
        if addr not in self.states:
            return None

        addr_map = self.states[addr]
        if pre_or_post not in addr_map:
            return None

        return addr_map[pre_or_post]

    def _offset_for(self, addr, pre_or_post, reg):
        try:
            s = self._state_for(addr, pre_or_post)
            if s is None:
                return TOP
            regval = dict(s.regs)[reg]
        except KeyError:
            return TOP
        if regval is TOP or type(regval) is Constant:
            return TOP
        elif regval is BOTTOM:
            # we don't really know what it should be. return TOP instead.
            return TOP
        else:
            return regval.offset

    def offset_after(self, addr, reg):
        return self._offset_for(addr, "post", reg)

    def offset_before(self, addr, reg):
        return self._offset_for(addr, "pre", reg)

    def offset_after_block(self, block_addr, reg):
        if block_addr not in self._blocks:
            return TOP
        instr_addrs = self._blocks[block_addr].instruction_addrs
        if len(instr_addrs) == 0:
            return TOP
        else:
            return self.offset_after(instr_addrs[-1], reg)

    def offset_before_block(self, block_addr, reg):
        if block_addr not in self._blocks:
            return TOP
        instr_addrs = self._blocks[block_addr].instruction_addrs
        if len(instr_addrs) == 0:
            return TOP
        else:
            return self.offset_before(instr_addrs[0], reg)

    def _constant_for(self, addr, pre_or_post, reg):
        try:
            s = self._state_for(addr, pre_or_post)
            if s is None:
                return TOP
            regval = dict(s.regs)[reg]
        except KeyError:
            return TOP
        if type(regval) is Constant:
            return regval.val
        return TOP

    def constant_after(self, addr, reg):
        return self._constant_for(addr, "post", reg)

    def constant_before(self, addr, reg):
        return self._constant_for(addr, "pre", reg)

    def constant_after_block(self, block_addr, reg):
        if block_addr not in self._blocks:
            return TOP
        instr_addrs = self._blocks[block_addr].instruction_addrs
        if len(instr_addrs) == 0:
            return TOP
        else:
            return self.constant_after(instr_addrs[-1], reg)

    def constant_before_block(self, block_addr, reg):
        if block_addr not in self._blocks:
            return TOP
        instr_addrs = self._blocks[block_addr].instruction_addrs
        if len(instr_addrs) == 0:
            return TOP
        else:
            return self.constant_before(instr_addrs[0], reg)

    @property
    def inconsistent(self):
        return any(self.inconsistent_for(r) for r in self.reg_offsets)

    def inconsistent_for(self, reg):
        for endpoint in self._func.endpoints:
            if self.offset_after_block(endpoint.addr, reg) is TOP:
                return True
        return False

    def offsets_for(self, reg):
        return [
            o for block in self._func.blocks if (o := self.offset_after_block(block.addr, reg)) not in (TOP, BOTTOM)
        ]

    #
    # Overridable methods
    #

    def _pre_analysis(self):
        pass

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

    def _get_register(self, offset):
        name = self.project.arch.register_names[offset]
        size = self.project.arch.registers[name][1]
        return Register(offset, size * self.project.arch.byte_width)

    def _initial_abstract_state(self, node: BlockNode):
        if self._func is None:
            # in single-block mode, at the beginning of the block, we set each tracking register to their initial values
            initial_regs = {r: OffsetVal(self._get_register(r), 0) for r in self.reg_offsets}
        else:
            # function mode
            if node.addr == self._func.addr:
                # at the beginning of the function, we set each tracking register to their "initial values"
                initial_regs = {r: OffsetVal(self._get_register(r), 0) for r in self.reg_offsets}
            else:
                # if we are requesting initial states for blocks that are not the starting point of this function, we
                # are probably dealing with dangling blocks (those without a predecessor due to CFG recovery failures).
                # Setting register values to fresh ones will cause problems down the line when merging with normal
                # register values happen. therefore, we set their values to BOTTOM. these BOTTOMs will be replaced once
                # a merge with normal blocks happen.
                initial_regs = {r: BOTTOM for r in self.reg_offsets}

        return StackPointerTrackerState(regs=initial_regs, memory={}, is_tracking_memory=self.track_mem).freeze()

    def _set_state(self, addr, new_val, pre_or_post):
        previous_val = self._state_for(addr, pre_or_post)
        if previous_val is not None:
            new_val = previous_val.merge(new_val)
        if addr not in self.states:
            self.states[addr] = {}
        self.states[addr][pre_or_post] = new_val

    def _set_post_state(self, addr, new_val):
        self._set_state(addr, new_val, "post")

    def _set_pre_state(self, addr, new_val):
        self._set_state(addr, new_val, "pre")

    def _run_on_node(self, node: BlockNode, state):
        block = self.project.factory.block(node.addr, size=node.size, cross_insn_opt=self.cross_insn_opt)
        self._blocks[node.addr] = block

        state = state.unfreeze()
        _l.debug("START:       Running on block at %x", node.addr)
        _l.debug("Regs: %s", state.regs)
        _l.debug("Mem: %s", state.memory)
        curr_stmt_start_addr = None

        vex_block = None
        try:
            vex_block = block.vex
        except SimTranslationError:
            pass

        if node.addr in self._reg_value_at_block_start:
            for reg, val in self._reg_value_at_block_start[node.addr].items():
                state.put(reg, val)

        if vex_block is not None:
            if isinstance(vex_block, pyvex.IRSB):
                curr_stmt_start_addr = self._process_vex_irsb(node, vex_block, state)
            elif pypcode is not None and isinstance(vex_block, pcode.lifter.IRSB):
                curr_stmt_start_addr = self._process_pcode_irsb(node, vex_block, state)
            else:
                raise NotImplementedError(f"Unsupported block type {type(vex_block)}")

        if curr_stmt_start_addr is not None:
            self._set_post_state(curr_stmt_start_addr, state.freeze())

        _l.debug("FINISH:      After running on block at %x", node.addr)
        _l.debug("Regs: %s", state.regs)
        _l.debug("Mem: %s", state.memory)

        output_state = state.freeze()
        return None, output_state

    def _process_vex_irsb(self, node, vex_block: pyvex.IRSB, state: StackPointerTrackerState) -> int:
        tmps = {}
        curr_stmt_start_addr = None

        def _resolve_expr(expr):
            if type(expr) is pyvex.IRExpr.Binop:
                arg0, arg1 = expr.args
                if expr.op.startswith("Iop_Add"):
                    arg0_expr = _resolve_expr(arg0)
                    if arg0_expr is None:
                        raise CouldNotResolveException()
                    if arg0_expr is BOTTOM:
                        return BOTTOM
                    arg1_expr = _resolve_expr(arg1)
                    if arg1_expr is None:
                        raise CouldNotResolveException()
                    if arg1_expr is BOTTOM:
                        return BOTTOM
                    return arg0_expr + arg1_expr
                elif expr.op.startswith("Iop_Sub"):
                    arg0_expr = _resolve_expr(arg0)
                    if arg0_expr is None:
                        raise CouldNotResolveException()
                    if arg0_expr is BOTTOM:
                        return BOTTOM
                    arg1_expr = _resolve_expr(arg1)
                    if arg1_expr is None:
                        raise CouldNotResolveException()
                    if arg1_expr is BOTTOM:
                        return BOTTOM
                    return arg0_expr - arg1_expr
                elif expr.op.startswith("Iop_And"):
                    # handle stack pointer alignments
                    arg0_expr = _resolve_expr(arg0)
                    arg1_expr = _resolve_expr(arg1)
                    if (
                        isinstance(arg1_expr, (Register, OffsetVal))
                        and isinstance(arg0_expr, Constant)
                        and is_alignment_mask(arg0_expr.val)
                    ):
                        return arg1_expr
                    if (
                        isinstance(arg0_expr, (Register, OffsetVal))
                        and isinstance(arg1_expr, Constant)
                        and is_alignment_mask(arg1_expr.val)
                    ):
                        return arg0_expr
                elif expr.op.startswith("Iop_CmpEQ"):
                    arg0_expr = _resolve_expr(arg0)
                    arg1_expr = _resolve_expr(arg1)
                    if isinstance(arg0_expr, (Register, OffsetVal)) and isinstance(arg1_expr, (Register, OffsetVal)):
                        return Eq(arg0_expr, arg1_expr)
                raise CouldNotResolveException()
            elif type(expr) is pyvex.IRExpr.RdTmp and expr.tmp in tmps and tmps[expr.tmp] is not None:
                return tmps[expr.tmp]
            elif type(expr) is pyvex.IRExpr.Const:
                return Constant(expr.con.value)
            elif type(expr) is pyvex.IRExpr.Get:
                return state.get(expr.offset)
            elif type(expr) is pyvex.IRExpr.Unop:
                m = IROP_CONVERT_REGEX.match(expr.op)
                if m is not None:
                    from_bits = int(m.group(1))
                    # from_unsigned = m.group(2) == "U"
                    to_bits = int(m.group(3))
                    # to_unsigned = m.group(4) == "U"
                    v = resolve_expr(expr.args[0])
                    if isinstance(v, Constant):
                        if from_bits > to_bits:
                            # truncation
                            mask = (1 << to_bits) - 1
                            return Constant(v.val & mask)
                        return v
                    elif isinstance(v, Eq):
                        return v
                    return TOP
            elif self.track_mem and type(expr) is pyvex.IRExpr.Load:
                return state.load(_resolve_expr(expr.addr))
            raise CouldNotResolveException()

        def resolve_expr(expr):
            try:
                return _resolve_expr(expr)
            except CouldNotResolveException:
                return TOP

        def resolve_stmt(stmt):
            if type(stmt) is pyvex.IRStmt.WrTmp:
                tmps[stmt.tmp] = resolve_expr(stmt.data)
            elif self.track_mem and type(stmt) is pyvex.IRStmt.Store:
                state.store(resolve_expr(stmt.addr), resolve_expr(stmt.data))
            elif type(stmt) is pyvex.IRStmt.Put:
                if exit_observed and stmt.offset == self.project.arch.sp_offset:
                    return
                state.put(stmt.offset, resolve_expr(stmt.data))
            else:
                raise CouldNotResolveException()

        exit_observed = False
        for stmt in vex_block.statements:
            if type(stmt) is pyvex.IRStmt.IMark:
                if curr_stmt_start_addr is not None:
                    # we've reached a new instruction. Time to store the post state
                    self._set_post_state(curr_stmt_start_addr, state.freeze())
                curr_stmt_start_addr = stmt.addr + stmt.delta
                self._set_pre_state(curr_stmt_start_addr, state.freeze())
            elif (
                type(stmt) is pyvex.IRStmt.Exit
                and curr_stmt_start_addr in vex_block.instruction_addresses
                and vex_block.instruction_addresses.index(curr_stmt_start_addr) == vex_block.instructions - 1
            ):
                exit_observed = True
                if (
                    type(stmt.guard) is pyvex.IRExpr.RdTmp
                    and stmt.guard.tmp in tmps
                    and isinstance(stmt.dst, pyvex.IRConst.IRConst)
                ):
                    guard = tmps[stmt.guard.tmp]
                    if isinstance(guard, Eq):
                        for reg, val in state.regs.items():
                            if reg in {self.project.arch.sp_offset, self.project.arch.bp_offset}:
                                cond = None
                                if val == guard.val0:
                                    cond = guard.val1
                                elif val == guard.val1:
                                    cond = guard.val0
                                if cond is not None:
                                    self._reg_value_at_block_start[stmt.dst.value][reg] = cond
            else:
                try:
                    resolve_stmt(stmt)
                except CouldNotResolveException:
                    pass

        # stack pointer adjustment
        if self.project.arch.sp_offset in self.reg_offsets and vex_block.jumpkind == "Ijk_Call":
            if self.project.arch.call_pushes_ret:
                # pop the return address on the stack
                try:
                    v = state.get(self.project.arch.sp_offset)
                    if v is BOTTOM:
                        incremented = BOTTOM
                    else:
                        incremented = v + Constant(self.project.arch.bytes)
                    state.put(self.project.arch.sp_offset, incremented)
                except CouldNotResolveException:
                    pass
            # who are we calling?
            callees = [] if self._func is None else self._find_callees(node)
            if callees:
                callee_cleanups = [
                    callee
                    for callee in callees
                    if callee.calling_convention is not None and callee.calling_convention.CALLEE_CLEANUP
                ]
                if callee_cleanups:
                    # found callee clean-up cases...
                    try:
                        v = state.get(self.project.arch.sp_offset)
                        if v is BOTTOM:
                            incremented = BOTTOM
                        elif callee_cleanups[0].prototype is not None:
                            num_args = len(callee_cleanups[0].prototype.args)
                            incremented = v + Constant(self.project.arch.bytes * num_args)
                        state.put(self.project.arch.sp_offset, incremented)
                    except CouldNotResolveException:
                        pass

        return curr_stmt_start_addr

    def _process_pcode_irsb(self, node, pcode_irsb: "pcode.lifter.IRSB", state: StackPointerTrackerState) -> int:
        unique = {}
        curr_stmt_start_addr = None

        def _resolve_expr(varnode: "pypcode.Varnode"):
            if varnode.space.name == "register":
                return state.get(varnode.offset)
            elif varnode.space.name == "unique":
                key = (varnode.offset, varnode.size)
                if key not in unique:
                    raise CouldNotResolveException()
                return unique[key]
            elif varnode.space.name == "const":
                return Constant(varnode.offset)
            else:
                raise CouldNotResolveException()

        def resolve_expr(varnode: "pypcode.Varnode"):
            try:
                return _resolve_expr(varnode)
            except CouldNotResolveException:
                return TOP

        def resolve_op(op: "pypcode.PcodeOp"):
            if op.opcode == pypcode.OpCode.INT_ADD and len(op.inputs) == 2:
                input0, input1 = op.inputs
                input0_v = resolve_expr(input0)
                input1_v = resolve_expr(input1)
                if isinstance(input0_v, (Register, OffsetVal)) and isinstance(input1_v, Constant):
                    v = input0_v + input1_v
                else:
                    raise CouldNotResolveException()
            elif op.opcode == pypcode.OpCode.COPY:
                v = resolve_expr(op.inputs[0])
            else:
                # unsupported opcode
                raise CouldNotResolveException()

            # write the output
            if op.output.space.name == "unique":
                offset, size = op.output.offset, op.output.size
                unique[(offset, size)] = v
            elif op.output.space.name == "register":
                state.put(op.output.offset, v)
            else:
                raise CouldNotResolveException()

        is_call = False
        for op in pcode_irsb._ops:
            if op.opcode == pypcode.OpCode.IMARK:
                if curr_stmt_start_addr is not None:
                    # we've reached a new instruction. Time to store the post state
                    self._set_post_state(curr_stmt_start_addr, state.freeze())
                curr_stmt_start_addr = op.inputs[0].offset
                self._set_pre_state(curr_stmt_start_addr, state.freeze())
            else:
                try:
                    resolve_op(op)
                except CouldNotResolveException:
                    pass

                is_call |= op.opcode == pypcode.OpCode.CALL

        # stack pointer adjustment
        if self.project.arch.sp_offset in self.reg_offsets and is_call:
            if self.project.arch.call_pushes_ret:
                # pop the return address on the stack
                try:
                    v = state.get(self.project.arch.sp_offset)
                    if v is BOTTOM:
                        incremented = BOTTOM
                    else:
                        incremented = v + Constant(self.project.arch.bytes)
                    state.put(self.project.arch.sp_offset, incremented)
                except CouldNotResolveException:
                    pass
            # who are we calling?
            callees = self._find_callees(node)
            if callees:
                callee_cleanups = [
                    callee
                    for callee in callees
                    if callee.calling_convention is not None and callee.calling_convention.CALLEE_CLEANUP
                ]
                if callee_cleanups:
                    # found callee clean-up cases...
                    try:
                        v = state.get(self.project.arch.sp_offset)
                        if v is BOTTOM:
                            incremented = BOTTOM
                        elif callee_cleanups[0].prototype is not None:
                            num_args = len(callee_cleanups[0].prototype.args)
                            incremented = v + Constant(self.project.arch.bytes * num_args)
                        state.put(self.project.arch.sp_offset, incremented)
                    except CouldNotResolveException:
                        pass

        return curr_stmt_start_addr

    def _widen_states(self, *states):
        assert len(states) == 2
        merged, _ = self._merge_states(None, *states)
        if len(merged.memory) > 5:
            _l.info("Encountered too many memory writes in stack pointer tracking. Abandoning memory tracking.")
            merged = merged.unfreeze().give_up_on_memory_tracking().freeze()
        return merged

    def _merge_states(self, node, *states: StackPointerTrackerState):
        merged_state = states[0]
        for other in states[1:]:
            merged_state = merged_state.merge(other)
        return merged_state, merged_state == states[0]

    def _find_callees(self, node) -> list[Function]:
        callees: list[Function] = []
        for _, dst, data in self._func.transition_graph.out_edges(node, data=True):
            if data.get("type") == "call":
                if isinstance(dst, Function):
                    callees.append(dst)
        return callees


AnalysesHub.register_default("StackPointerTracker", StackPointerTracker)
