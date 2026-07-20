# pylint:disable=abstract-method
from __future__ import annotations

import bisect
import contextlib
import logging
import re
from collections import defaultdict
from typing import TYPE_CHECKING, Any

import pyvex
from archinfo.arch_arm import is_arm_arch

try:
    import pypcode

    from angr.engines import pcode
except ImportError:
    pypcode = None
    pcode = None

from angr.analyses.analysis import AnalysesHub
from angr.analyses.forward_analysis import ForwardAnalysis, visitors
from angr.block import BlockNode
from angr.calling_conventions import SimStackArg
from angr.codenode import FuncNode
from angr.errors import SimTranslationError
from angr.knowledge_plugins import Function
from angr.utils.constants import is_alignment_mask
from angr.utils.types import dereference_simtype_by_lib

from .analysis import Analysis

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
        return other + self

    def __sub__(self, other):
        if type(self) is type(other):
            return Constant(self.val - other.val)
        raise CouldNotResolveException


class Register:
    """
    Represent a register.
    """

    __slots__ = ("bitlen", "offset")

    def __init__(self, offset, bitlen):
        self.offset = offset
        self.bitlen = bitlen

    def __hash__(self):
        return hash((Register, self.offset))

    def __eq__(self, other):
        if type(other) is Register or isinstance(other, Register):
            return self.offset == other.offset
        return False

    def __add__(self, other) -> OffsetVal:
        if type(other) is Constant:
            return OffsetVal(self, other.val)
        raise CouldNotResolveException

    def __repr__(self):
        return str(self.offset)


class OffsetVal:
    """
    Represent a value with an offset added.
    """

    __slots__ = (
        "_offset",
        "_reg",
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
        raise CouldNotResolveException

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if type(other) is Constant:
            return OffsetVal(self._reg, self._offset - other.val & (2**self.reg.bitlen - 1))
        raise CouldNotResolveException

    def __rsub__(self, other):
        raise CouldNotResolveException

    def __eq__(self, other):
        if type(other) is OffsetVal or isinstance(other, OffsetVal):
            return self.reg == other.reg and self.offset == other.offset
        return False

    def __lt__(self, other):
        if isinstance(other, OffsetVal):
            return self.reg == other.reg and self.offset < other.offset
        return False

    def __le__(self, other):
        if isinstance(other, OffsetVal):
            return self.reg == other.reg and self.offset <= other.offset
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

    __slots__ = "is_tracking_memory", "memory", "regs", "resilient"

    def __init__(
        self,
        regs,
        memory,
        is_tracking_memory,
        resilient,
    ):
        self.regs = regs
        self.memory = memory
        self.is_tracking_memory = is_tracking_memory
        self.resilient = resilient

    def unfreeze(self):
        return StackPointerTrackerState(dict(self.regs), dict(self.memory), self.is_tracking_memory, self.resilient)

    def __hash__(self):
        if self.is_tracking_memory:
            return hash((FrozenStackPointerTrackerState, self.regs, self.memory, self.is_tracking_memory))
        return hash((FrozenStackPointerTrackerState, self.regs, self.is_tracking_memory))

    def merge(
        self, other, addr: int, reg_merge_cache: dict[tuple[int, int], Any], mem_merge_cache: dict[tuple[int, int], Any]
    ):
        return self.unfreeze().merge(other.unfreeze(), addr, reg_merge_cache, mem_merge_cache).freeze()

    def __eq__(self, other):
        if type(other) is FrozenStackPointerTrackerState or isinstance(other, FrozenStackPointerTrackerState):
            cond1 = self.regs == other.regs and self.is_tracking_memory == other.is_tracking_memory
            if self.is_tracking_memory:
                cond1 &= self.memory == other.memory
            return cond1
        return False


MAX_MEMORY_ENTRIES = 100


class StackPointerTrackerState:
    """
    Abstract state for StackPointerTracker analysis.
    """

    __slots__ = "_dirty_mem", "_dirty_regs", "is_tracking_memory", "memory", "regs", "resilient"

    def __init__(self, regs, memory, is_tracking_memory, resilient: bool):
        self.regs = regs
        if is_tracking_memory:
            self.memory = memory
        else:
            self.memory = {}
        self.is_tracking_memory = is_tracking_memory
        self.resilient = resilient
        # Bookkeeping for per-instruction delta capture by StackPointerTracker. `put`/`store` add the
        # written register offset / memory address here; `pop_dirty` then materializes a delta dict at
        # IMark boundaries and resets the sets. Avoids snapshotting and diffing the full state at every
        # instruction. Not propagated by `copy`/`freeze`: each fresh state starts with empty dirty sets,
        # since these markers are only meaningful within a single `_run_on_node` IR replay.
        self._dirty_regs: set[int] = set()
        self._dirty_mem: set[int] = set()

    def give_up_on_memory_tracking(self):
        self.memory = {}
        self.is_tracking_memory = False
        self._dirty_mem = set()
        return self

    def store(self, addr, val):
        # strong update
        if self.is_tracking_memory and val is not None and addr is not None:
            self.memory[addr] = val
            self._dirty_mem.add(addr)

        if len(self.memory) >= MAX_MEMORY_ENTRIES:
            self.give_up_on_memory_tracking()

    def pop_dirty(self):
        # Return (reg_delta, mem_delta) capturing the *current* values of every register / memory cell
        # written since the last call (or since construction), then reset the dirty sets. Called at each
        # IMark boundary so that StackPointerTracker can record one delta entry per instruction.
        reg_delta = {r: self.regs[r] for r in self._dirty_regs if r in self.regs}
        mem_delta = {m: self.memory[m] for m in self._dirty_mem if m in self.memory}
        self._dirty_regs = set()
        self._dirty_mem = set()
        return reg_delta, mem_delta

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

    def put(self, reg, val, force: bool = False):
        # strong update, but we only update values for registers that are already in self.regs and ignore all other
        # registers. obviously, self.regs should be initialized with registers that should be considered during
        # tracking,
        if reg in self.regs or force:
            self.regs[reg] = val
            self._dirty_regs.add(reg)

    def copy(self):
        return StackPointerTrackerState(self.regs.copy(), self.memory.copy(), self.is_tracking_memory, self.resilient)

    def freeze(self):
        return FrozenStackPointerTrackerState(
            frozenset(self.regs.items()), frozenset(self.memory.items()), self.is_tracking_memory, self.resilient
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
        return hash((StackPointerTrackerState, self.regs, self.is_tracking_memory))

    def merge(
        self, other, addr: int, reg_merge_cache: dict[tuple[int, int], Any], mem_merge_cache: dict[tuple[int, int], Any]
    ):
        return StackPointerTrackerState(
            regs=_dict_merge(self.regs, other.regs, self.resilient, addr, reg_merge_cache),
            memory=_dict_merge(self.memory, other.memory, self.resilient, addr, mem_merge_cache),
            is_tracking_memory=self.is_tracking_memory and other.is_tracking_memory,
            resilient=self.resilient or other.resilient,
        )


def _dict_merge(d1, d2, resilient: bool, addr: int, merge_cache: dict[tuple[int, int], Any]):
    all_keys = set(d1.keys()) | set(d2.keys())
    merged = {}
    for k in all_keys:
        if k not in d1 or d1[k] is TOP or (k not in d2 or d2[k] is TOP):
            merged[k] = TOP
        elif d1[k] is BOTTOM:
            merged[k] = d2[k]
        elif d2[k] is BOTTOM or d1[k] == d2[k]:
            merged[k] = d1[k]
        else:  # d1[k] != d2[k]
            if resilient and isinstance(d1[k], OffsetVal) and isinstance(d2[k], OffsetVal):
                if (addr, k) in merge_cache:
                    merged[k] = merge_cache[(addr, k)]
                else:
                    v = min(d1[k], d2[k])
                    merge_cache[(addr, k)] = v
                    merged[k] = v
            else:
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
        block: Block | None = None,
        track_memory=True,
        cross_insn_opt=True,
        initial_reg_values=None,
        resilient: bool = True,
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
        self.reg_values: dict[int, dict[int, Any]] = defaultdict(dict)
        self.mem_values: dict[int, dict[int, Any]] = defaultdict(dict)
        self.reg_deltas: dict[int, dict[int, dict[int, Any]]] = {}
        self.mem_deltas: dict[int, dict[int, dict[int, Any]]] = {}
        self._block_meta: dict[int, tuple[bool, bool]] = {}
        self._sorted_block_addrs: list[int] = []
        self._blocks = {}
        self._reg_value_at_block_start = defaultdict(dict)
        self.cross_insn_opt = cross_insn_opt
        self._resilient = resilient
        # in resilience mode, cache previously merged values to ensure we reach a fixed point
        self._reg_merge_cache = {}
        self._mem_merge_cache = {}

        if initial_reg_values:
            block_start_addr = func.addr if func is not None else block.addr  # type: ignore
            self._reg_value_at_block_start[block_start_addr] = initial_reg_values

        self._itstate_regoffset = None
        if is_arm_arch(self.project.arch):
            self._itstate_regoffset = self.project.arch.registers["itstate"][0]

        _l.debug("Running on function %r", self._func)
        self._analyze()

    def _block_addr_for_insn(self, insn_addr: int) -> int | None:
        idx = bisect.bisect_right(self._sorted_block_addrs, insn_addr) - 1
        if idx < 0:
            return None
        block_addr = self._sorted_block_addrs[idx]
        block = self._blocks.get(block_addr)
        if block is None or insn_addr >= block_addr + block.size:
            return None
        return block_addr

    def _value_for(self, addr, pre_or_post, store, deltas, key):
        block_addr = self._block_addr_for_insn(addr)
        if block_addr is None:
            return TOP
        per_block = store.get(key)
        if per_block is None or block_addr not in per_block:
            return TOP
        val = per_block[block_addr]
        target = addr - block_addr
        block_deltas = deltas.get(block_addr)
        if block_deltas:
            include_target = pre_or_post == "post"
            for off in sorted(block_deltas):
                if off > target or (off == target and not include_target):
                    break
                inner = block_deltas[off]
                if key in inner:
                    val = inner[key]
        return val

    def _offset_for(self, addr, pre_or_post, reg):
        regval = self._value_for(addr, pre_or_post, self.reg_values, self.reg_deltas, reg)
        if regval is TOP or regval is BOTTOM or type(regval) is Constant:
            return TOP
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
        return self.offset_after(instr_addrs[-1], reg)

    def offset_before_block(self, block_addr, reg):
        if block_addr not in self._blocks:
            return TOP
        instr_addrs = self._blocks[block_addr].instruction_addrs
        if len(instr_addrs) == 0:
            return TOP
        return self.offset_before(instr_addrs[0], reg)

    def _constant_for(self, addr, pre_or_post, reg):
        regval = self._value_for(addr, pre_or_post, self.reg_values, self.reg_deltas, reg)
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
        return self.constant_after(instr_addrs[-1], reg)

    def constant_before_block(self, block_addr, reg):
        if block_addr not in self._blocks:
            return TOP
        instr_addrs = self._blocks[block_addr].instruction_addrs
        if len(instr_addrs) == 0:
            return TOP
        return self.constant_before(instr_addrs[0], reg)

    @property
    def inconsistent(self):
        return any(self.inconsistent_for(r) for r in self.reg_offsets)

    def inconsistent_for(self, reg):
        if self._func is None:
            raise ValueError("inconsistent_for() is only supported in function mode")
        return any(self.offset_after_block(endpoint.addr, reg) is TOP for endpoint in self._func.endpoints)

    def offsets_for(self, reg):
        if self._func is None:
            raise ValueError("offsets_for() is only supported in function mode")
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

    def _get_register(self, offset) -> Register:
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
                initial_regs = dict.fromkeys(self.reg_offsets, BOTTOM)

        return StackPointerTrackerState(
            regs=initial_regs, memory={}, is_tracking_memory=self.track_mem, resilient=self._resilient
        ).freeze()

    def _merge_into_block_start(self, block_addr: int, state: StackPointerTrackerState) -> StackPointerTrackerState:
        """
        Merge ``state`` (this iteration's block-start) with whatever is already stored for ``block_addr``,
        write the merged result back, and return it.
        """
        if block_addr in self._block_meta:
            prev_regs = {
                r: per_block[block_addr] for r, per_block in self.reg_values.items() if block_addr in per_block
            }
            prev_mem = {m: per_block[block_addr] for m, per_block in self.mem_values.items() if block_addr in per_block}
            prev_itm, prev_res = self._block_meta[block_addr]
            prev = StackPointerTrackerState(prev_regs, prev_mem, prev_itm, prev_res)
            state = prev.merge(state, block_addr, self._reg_merge_cache, self._mem_merge_cache)
        for r, v in state.regs.items():
            self.reg_values[r][block_addr] = v
        for m, v in state.memory.items():
            self.mem_values[m][block_addr] = v
        self._block_meta[block_addr] = (state.is_tracking_memory, state.resilient)
        return state

    def _record_delta(self, block_addr: int, insn_offset: int, reg_delta: dict, mem_delta: dict):
        if reg_delta:
            self.reg_deltas.setdefault(block_addr, {})[insn_offset] = reg_delta
        if mem_delta:
            self.mem_deltas.setdefault(block_addr, {})[insn_offset] = mem_delta

    def _run_on_node(self, node: BlockNode, state):
        block = self.project.factory.block(node.addr, size=node.size, cross_insn_opt=self.cross_insn_opt)
        self._blocks[node.addr] = block
        if not self._sorted_block_addrs or self._sorted_block_addrs[-1] != node.addr:
            idx = bisect.bisect_left(self._sorted_block_addrs, node.addr)
            if idx >= len(self._sorted_block_addrs) or self._sorted_block_addrs[idx] != node.addr:
                self._sorted_block_addrs.insert(idx, node.addr)

        state = state.unfreeze()
        _l.debug("START:       Running on block at %x", node.addr)
        _l.debug("Regs: %s", state.regs)
        _l.debug("Mem: %s", state.memory)
        curr_stmt_start_addr = None

        vex_block = None
        with contextlib.suppress(SimTranslationError):
            vex_block = block.vex

        if node.addr in self._reg_value_at_block_start:
            for reg, val in self._reg_value_at_block_start[node.addr].items():
                state.put(reg, val)

        # merge this iteration's block-start state with what's already stored, and use the merged state going forward
        state = self._merge_into_block_start(node.addr, state)

        # deltas are deterministic given the (merged) block-start state, so regenerate from scratch
        self.reg_deltas.pop(node.addr, None)
        self.mem_deltas.pop(node.addr, None)
        # discard any dirty markers carried over from setup; only IR-driven changes should be captured as deltas
        state.pop_dirty()

        if vex_block is not None:
            if isinstance(vex_block, pyvex.IRSB):
                curr_stmt_start_addr = self._process_vex_irsb(node, vex_block, state)
            elif pypcode is not None and isinstance(vex_block, pcode.lifter.IRSB):  # type: ignore
                curr_stmt_start_addr = self._process_pcode_irsb(node, vex_block, state)
            else:
                raise NotImplementedError(f"Unsupported block type {type(vex_block)}")

        if curr_stmt_start_addr is not None:
            reg_delta, mem_delta = state.pop_dirty()
            self._record_delta(node.addr, curr_stmt_start_addr - node.addr, reg_delta, mem_delta)

        _l.debug("FINISH:      After running on block at %x", node.addr)
        _l.debug("Regs: %s", state.regs)
        _l.debug("Mem: %s", state.memory)

        output_state = state.freeze()
        return None, output_state

    def _process_vex_irsb(self, node, vex_block: pyvex.IRSB, state: StackPointerTrackerState) -> int | None:
        tmps = {}
        curr_stmt_start_addr = None

        def _resolve_expr(expr):
            if type(expr) is pyvex.IRExpr.Binop:
                arg0, arg1 = expr.args
                if expr.op.startswith("Iop_Add"):
                    arg0_expr = _resolve_expr(arg0)
                    if arg0_expr is None:
                        raise CouldNotResolveException
                    if arg0_expr is BOTTOM:
                        return BOTTOM
                    arg1_expr = _resolve_expr(arg1)
                    if arg1_expr is None:
                        raise CouldNotResolveException
                    if arg1_expr is BOTTOM:
                        return BOTTOM
                    return arg0_expr + arg1_expr  # type: ignore
                if expr.op.startswith("Iop_Sub"):
                    arg0_expr = _resolve_expr(arg0)
                    if arg0_expr is None:
                        raise CouldNotResolveException
                    if arg0_expr is BOTTOM:
                        return BOTTOM
                    arg1_expr = _resolve_expr(arg1)
                    if arg1_expr is None:
                        raise CouldNotResolveException
                    if arg1_expr is BOTTOM:
                        return BOTTOM
                    return arg0_expr - arg1_expr  # type: ignore
                if expr.op.startswith("Iop_And"):
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
                    # also handle bitwise-and between constants
                    if isinstance(arg0_expr, Constant) and isinstance(arg1_expr, Constant):
                        return Constant(arg0_expr.val & arg1_expr.val)
                elif expr.op.startswith("Iop_Xor"):
                    # handle bitwise-xor between constants
                    arg0_expr = _resolve_expr(arg0)
                    arg1_expr = _resolve_expr(arg1)
                    if isinstance(arg0_expr, Constant) and isinstance(arg1_expr, Constant):
                        return Constant(arg0_expr.val ^ arg1_expr.val)
                elif expr.op.startswith("Iop_CmpEQ"):
                    arg0_expr = _resolve_expr(arg0)
                    arg1_expr = _resolve_expr(arg1)
                    if isinstance(arg0_expr, (Register, OffsetVal)) and isinstance(arg1_expr, (Register, OffsetVal)):
                        return Eq(arg0_expr, arg1_expr)
                elif expr.op.startswith("Iop_CmpNE"):
                    arg0_expr = _resolve_expr(arg0)
                    arg1_expr = _resolve_expr(arg1)
                    if isinstance(arg0_expr, Constant) and isinstance(arg1_expr, Constant):
                        return Constant(1 if arg0_expr.val == arg1_expr.val else 0)
                elif expr.op.startswith("Iop_Shr"):
                    arg0_expr = _resolve_expr(arg0)
                    arg1_expr = _resolve_expr(arg1)
                    if isinstance(arg0_expr, Constant) and isinstance(arg1_expr, Constant):
                        return Constant(arg0_expr.val >> arg1_expr.val)
                raise CouldNotResolveException
            if type(expr) is pyvex.IRExpr.RdTmp and expr.tmp in tmps and tmps[expr.tmp] is not None:
                return tmps[expr.tmp]
            if type(expr) is pyvex.IRExpr.Const:
                return Constant(expr.con.value)
            if type(expr) is pyvex.IRExpr.Get:
                if self._itstate_regoffset is not None and expr.offset == self._itstate_regoffset:
                    return Constant(0)
                return state.get(expr.offset)
            if type(expr) is pyvex.IRExpr.ITE:
                cond = _resolve_expr(expr.cond)
                if isinstance(cond, Constant):
                    return _resolve_expr(expr.iftrue) if cond.val == 1 else _resolve_expr(expr.iffalse)
            if type(expr) is pyvex.IRExpr.Unop:
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
                    if isinstance(v, Eq):
                        return v
                    return TOP
            elif type(expr) is pyvex.IRExpr.CCall and expr.callee.name == "armg_calculate_condition":
                # this is a hack for handling ARM THUMB conditional instructions and may not always work...
                return Constant(0)
            elif self.track_mem and type(expr) is pyvex.IRExpr.Load:
                return state.load(_resolve_expr(expr.addr))
            raise CouldNotResolveException

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
                raise CouldNotResolveException

        exit_observed = False
        for stmt in vex_block.statements:
            if type(stmt) is pyvex.IRStmt.IMark:
                if curr_stmt_start_addr is not None:
                    # we've reached a new instruction. record the previous instruction's delta
                    reg_delta, mem_delta = state.pop_dirty()
                    self._record_delta(node.addr, curr_stmt_start_addr - node.addr, reg_delta, mem_delta)
                curr_stmt_start_addr = stmt.addr + stmt.delta
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
                with contextlib.suppress(CouldNotResolveException):
                    resolve_stmt(stmt)

        # stack pointer adjustment
        if self.project.arch.sp_offset in self.reg_offsets and vex_block.jumpkind == "Ijk_Call":
            if self.project.arch.call_pushes_ret:
                # pop the return address on the stack
                try:
                    v = state.get(self.project.arch.sp_offset)
                    incremented = BOTTOM if v is BOTTOM else v + Constant(self.project.arch.bytes)
                    state.put(self.project.arch.sp_offset, incremented)
                except CouldNotResolveException:
                    pass
            # who are we calling?
            callees = [] if self._func is None else self._find_callees(node)
            sp_adjusted = False
            if callees:
                if len(callees) == 1:
                    callee = callees[0]
                    if callee.info.get("is_rust_probestack", False):
                        # sp = sp - rax/eax right after returning from the call
                        rust_probe_stack_rax_regname: str | None = None
                        if self.project.arch.name == "AMD64":
                            rust_probe_stack_rax_regname = "rax"
                        elif self.project.arch.name == "X86":
                            rust_probe_stack_rax_regname = "eax"

                        if rust_probe_stack_rax_regname is not None:
                            for stmt in reversed(vex_block.statements):
                                if (
                                    isinstance(stmt, pyvex.IRStmt.Put)
                                    and stmt.offset == self.project.arch.registers[rust_probe_stack_rax_regname][0]
                                    and isinstance(stmt.data, pyvex.IRExpr.Const)
                                ):
                                    sp_adjusted = True
                                    state.put(stmt.offset, Constant(stmt.data.con.value), force=True)
                                    break

                    if not sp_adjusted and (callee.info.get("is_alloca_probe", False) or callee.name == "__chkstk"):
                        # sp = sp - rax, but it's adjusted within the callee
                        chkstk_stack_rax_regname: str | None = None
                        if self.project.arch.name == "AMD64":
                            chkstk_stack_rax_regname = "rax"
                        elif self.project.arch.name == "X86":
                            chkstk_stack_rax_regname = "eax"

                        if chkstk_stack_rax_regname is not None:
                            for stmt in reversed(vex_block.statements):
                                if (
                                    isinstance(stmt, pyvex.IRStmt.Put)
                                    and stmt.offset == self.project.arch.registers[chkstk_stack_rax_regname][0]
                                    and isinstance(stmt.data, pyvex.IRExpr.Const)
                                    and self.project.arch.sp_offset in state.regs
                                ):
                                    sp_adjusted = True
                                    sp_v = state.regs[self.project.arch.sp_offset]
                                    if sp_v is not None:
                                        sp_v -= Constant(stmt.data.con.value)
                                        state.put(self.project.arch.sp_offset, sp_v, force=True)  # sp -= OFFSET
                                        state.put(stmt.offset, Constant(0), force=True)  # rax = 0
                                    break

                callee_cleanups = [
                    callee
                    for callee in callees
                    if callee.calling_convention is not None
                    and callee.calling_convention.CALLEE_CLEANUP
                    and callee.prototype is not None
                ]
                if callee_cleanups:
                    # found callee clean-up cases...
                    callee = callee_cleanups[0]
                    assert callee.calling_convention is not None  # just to make pyright happy
                    try:
                        v = state.get(self.project.arch.sp_offset)
                        incremented = None
                        if v is BOTTOM:
                            incremented = BOTTOM
                        elif callee.prototype is not None:
                            proto = (
                                dereference_simtype_by_lib(callee.prototype, callee.prototype_libname)
                                if callee.prototype_libname
                                else callee.prototype
                            )
                            num_stack_args = len(
                                [
                                    arg_loc
                                    for arg_loc in callee.calling_convention.arg_locs(proto)
                                    if isinstance(arg_loc, SimStackArg)
                                ]
                            )
                            if num_stack_args > 0:
                                incremented = v + Constant(self.project.arch.bytes * num_stack_args)
                        if incremented is not None:
                            state.put(self.project.arch.sp_offset, incremented)
                    except CouldNotResolveException:
                        pass

        return curr_stmt_start_addr

    def _process_pcode_irsb(self, node, pcode_irsb: pcode.lifter.IRSB, state: StackPointerTrackerState) -> int | None:
        unique = {}
        curr_stmt_start_addr = None

        def _resolve_expr(varnode: pypcode.Varnode):
            if varnode.space.name == "register":
                return state.get(varnode.offset)
            if varnode.space.name == "unique":
                key = (varnode.offset, varnode.size)
                if key not in unique:
                    raise CouldNotResolveException
                return unique[key]
            if varnode.space.name == "const":
                return Constant(varnode.offset)
            raise CouldNotResolveException

        def resolve_expr(varnode: pypcode.Varnode):
            try:
                return _resolve_expr(varnode)
            except CouldNotResolveException:
                return TOP

        def resolve_op(op: pypcode.PcodeOp):
            if op.opcode == pypcode.OpCode.INT_ADD and len(op.inputs) == 2:
                input0, input1 = op.inputs
                input0_v = resolve_expr(input0)
                input1_v = resolve_expr(input1)
                if isinstance(input0_v, (Register, OffsetVal)) and isinstance(input1_v, Constant):
                    v = input0_v + input1_v
                else:
                    raise CouldNotResolveException
            elif op.opcode == pypcode.OpCode.COPY:
                v = resolve_expr(op.inputs[0])
            else:
                # unsupported opcode
                raise CouldNotResolveException

            # write the output
            if op.output.space.name == "unique":
                offset, size = op.output.offset, op.output.size
                unique[(offset, size)] = v
            elif op.output.space.name == "register":
                state.put(op.output.offset, v)
            else:
                raise CouldNotResolveException

        is_call = False
        for op in pcode_irsb._ops:
            if op.opcode == pypcode.OpCode.IMARK:
                if curr_stmt_start_addr is not None:
                    # we've reached a new instruction. record the previous instruction's delta
                    reg_delta, mem_delta = state.pop_dirty()
                    self._record_delta(node.addr, curr_stmt_start_addr - node.addr, reg_delta, mem_delta)
                curr_stmt_start_addr = op.inputs[0].offset
            else:
                with contextlib.suppress(CouldNotResolveException):
                    resolve_op(op)

                is_call |= op.opcode == pypcode.OpCode.CALL

        # stack pointer adjustment
        if self.project.arch.sp_offset in self.reg_offsets and is_call:
            if self.project.arch.call_pushes_ret:
                # pop the return address on the stack
                try:
                    v = state.get(self.project.arch.sp_offset)
                    incremented = BOTTOM if v is BOTTOM else v + Constant(self.project.arch.bytes)
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
                        incremented = None
                        if v is BOTTOM:
                            incremented = BOTTOM
                        elif callee_cleanups[0].prototype is not None:
                            num_args = len(callee_cleanups[0].prototype.args)
                            incremented = v + Constant(self.project.arch.bytes * num_args)
                        if incremented is not None:
                            state.put(self.project.arch.sp_offset, incremented)
                    except CouldNotResolveException:
                        pass

        return curr_stmt_start_addr

    def _merge_states(self, node, *states: FrozenStackPointerTrackerState):
        merged_state = states[0]
        for other in states[1:]:
            merged_state = merged_state.merge(other, node.addr, self._reg_merge_cache, self._mem_merge_cache)
        return merged_state, merged_state == states[0]

    def _find_callees(self, node) -> list[Function]:
        if self._func is None:
            raise ValueError("find_callees() is only supported in function mode")

        callees: list[Function] = []
        for _, dst, data in self._func.transition_graph.out_edges(node, data=True):
            if data.get("type") == "call" and isinstance(dst, FuncNode):
                func = self.kb.functions.get_by_addr(dst.addr)
                callees.append(func)
        return callees


AnalysesHub.register_default("StackPointerTracker", StackPointerTracker)
