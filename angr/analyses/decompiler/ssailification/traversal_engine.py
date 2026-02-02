from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING
from collections.abc import Iterable
from collections.abc import Callable


from angr.ailment.statement import Call, Store, ConditionalJump, CAS
from angr.ailment.expression import (
    Const,
    Convert,
    Extract,
    Insert,
    Register,
    StackBaseOffset,
    ITE,
    VEXCCallExpression,
    Tmp,
    DirtyExpression,
    Load,
    VirtualVariable,
)

from angr.code_location import AILCodeLocation
from angr.engines.light import SimEngineLightAIL
from angr.knowledge_plugins.functions.function import Function
from angr.project import Project
from angr.sim_type import PointerDisposition, SimTypePointer
from angr.utils.ssa import get_reg_offset_base
from angr.calling_conventions import default_cc
from .traversal_state import TraversalState, Value

if TYPE_CHECKING:
    from angr.analyses.decompiler.ssailification.ssailification import Def, Kind

CUTOFF = 15  # arbitrary; be mindful of performance as various parts will be O(N^2)


def offset_sort_key(v: tuple[int | None, int]) -> tuple[int, int, int, int]:
    # used for iterating over Value in a determinisitic order
    # moderately arbitrary. feel free to change as long as
    # - it produces a total ordering, i.e. f(a) == f(b) iff a == b
    # - it never returns None values, as these cannot be sorted
    return (v[1], 0 if v[0] is not None else 1, abs(v[0] or 0), 0 if v[0] is None or v[0] < 0 else 1)


@dataclass
class DefInfo:
    def_: Def
    kind: Kind
    loc: AILCodeLocation
    variable_offset: int  # offset from beginning of region to beginning of variable
    variable_size: int
    store_offset: int  # offset from beginning of region to beginning of store
    store_size: int
    supercedes: set[Def]

    @property
    def variable_range(self):
        return range(self.variable_offset, self.variable_offset + self.variable_size)

    @property
    def variable_endoffset(self):
        return self.variable_offset + self.variable_size


class SimEngineSSATraversal(SimEngineLightAIL[TraversalState, Value, None, None]):
    """
    This engine collects all register and stack variable locations and links them to the block of their creation.
    """

    def __init__(
        self,
        project: Project,
        simos,
        sp_tracker=None,
        bp_as_gpr: bool = False,
        stackvars: bool = False,
        use_tmps: bool = False,
        functions: Callable[[int | str], Function | None] | None = None,
    ):
        super().__init__(project)
        self.simos = simos
        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr
        self.stackvars = stackvars
        self.use_tmps = use_tmps
        self.functions = functions
        self.def_info: dict[Def, DefInfo] = {}
        self.pending_ptr_defines_nonlocal: dict[
            int, tuple[AILCodeLocation, StackBaseOffset, set[tuple[int, int]], bool]
        ] = {}
        # the state which skipped the last few statements; the state that breaks the loop
        self.hclb_side_exit_state: TraversalState | None = None

    def _is_top(self, expr):
        return not expr

    def _top(self, bits):
        return set()

    def _process_block_end(self, block, stmt_data, whitelist):
        # see comment in StackBaseOffset handler
        for k, (v1, v2) in self.state.pending_ptr_defines.items():
            if k not in self.pending_ptr_defines_nonlocal:
                self.pending_ptr_defines_nonlocal[k] = (v1, v2, set(), k not in self.state.live_stackvars)
                self.state.pending_ptr_defines_nonlocal_live.add(k)
        self.state.pending_ptr_defines.clear()  # just in case

    def finalize(self):
        for stack_offset, (loc, def_, suggestions, required) in self.pending_ptr_defines_nonlocal.items():
            if not required:
                continue
            full_offset, full_endoffset = stack_offset, stack_offset + 1
            for suggested_offset, suggested_size in suggestions:
                suggested_endoffset = suggested_offset + suggested_size
                full_offset = min(full_offset, suggested_offset)
                full_endoffset = max(full_endoffset, suggested_endoffset)

            self.perform_def(
                "stack",
                def_,
                full_offset,
                full_endoffset - full_offset,
                stack_offset,
                0,
                loc,
            )

        # sketchy situation. we want to make sure everything in the extern set
        # has exactly the same extents if they overlap at all. this is sorta a redo
        # of the unify code.
        mapping: defaultdict[int, set[Def]] = defaultdict(set)
        for def_, definfo in self.def_info.items():
            if definfo.kind != "stack" or not definfo.loc.is_extern:
                continue
            for suboffset in definfo.variable_range:
                mapping[suboffset].add(def_)

        current_extent = (0, 0)
        current_defs = set()

        def flush():
            for def2 in current_defs:
                definfo = self.def_info[def2]
                size2 = current_extent[1] - current_extent[0]
                definfo.variable_offset = current_extent[0]
                definfo.variable_size = size2

        for offset in sorted(mapping):
            for def_ in mapping[offset]:
                definfo = self.def_info[def_]

                if definfo.variable_offset >= current_extent[1] or current_extent[0] == current_extent[1]:
                    flush()
                    current_defs.clear()
                    current_extent = definfo.variable_offset, definfo.variable_endoffset

                current_defs.add(def_)
                current_extent = min(current_extent[0], definfo.variable_offset), max(
                    current_extent[1], definfo.variable_endoffset
                )
        flush()

    def _acodeloc(self):
        return AILCodeLocation(
            self.block.addr,
            self.block.idx,
            self.stmt_idx,
            self.ins_addr,
        )

    def perform_def(
        self,
        kind: Kind,
        def_: Def,
        variable_offset: int,
        variable_size: int,
        store_offset: int,
        store_size: int,
        loc: AILCodeLocation | None = None,
        supercedes: Iterable[Def] | None = None,
    ):
        loc = loc or self._acodeloc()
        assert (
            def_ not in self.def_info or self.def_info[def_].variable_size <= variable_size
        ), "redefinining a variable as smaller"
        assert (
            def_ not in self.def_info or self.def_info[def_].loc == loc or self.def_info[def_].loc.is_extern
        ), "claiming an expression defines at two different locs"
        definfo = DefInfo(
            def_,
            kind,
            loc,
            variable_offset,
            variable_size,
            store_offset,
            store_size,
            set(supercedes or ()),
        )
        self.def_info[def_] = definfo
        return definfo

    def stackvar_get(self, base_offset: int, extra_offset: int, base_size: int) -> Value:
        if extra_offset > 1 << (self.project.arch.bits - 1):
            extra_offset -= 1 << self.project.arch.bits
        offset = base_offset + min(extra_offset, 0)
        size = max(extra_offset, 0) + base_size
        full_offset, full_size, popped = self.state.stackvar_unify(offset, size)

        if base_offset in self.state.pending_ptr_defines_nonlocal_live:
            self.pending_ptr_defines_nonlocal.pop(base_offset, None)

        _, pending_def = self.state.pending_ptr_defines.pop(base_offset, (None, None))

        secret_stash = defaultdict(set)
        while True:  # this loop should run until the UH OH is never reached
            for popped_offset in popped:
                secret_stash[popped_offset].update(self.state.stackvar_defs.pop(popped_offset, set()))
                for def2 in secret_stash[popped_offset]:
                    self.state.stackvar_defs[full_offset].add(def2)
                    definfo = self.def_info[def2]
                    if definfo.variable_offset < full_offset or definfo.variable_endoffset > full_offset + full_size:
                        # UH OH. We have information from a parallel timeline about how big this var actually is...
                        full_offset, full_size, popped2 = self.state.stackvar_unify(
                            definfo.variable_offset, definfo.variable_size
                        )
                        popped.update(popped2)
                        break
                    definfo.variable_offset = full_offset
                    definfo.variable_size = full_size
                else:
                    continue
                break
            else:
                break

        defs = secret_stash.get(full_offset, set())
        if not defs:
            if pending_def is not None:
                # if this assert trips maybe consider gating all the redef stuff on the cond?
                # maybe also consider making def nullable in case of externs
                self.perform_def(
                    "stack",
                    pending_def,
                    full_offset,
                    full_size,
                    base_offset + extra_offset,
                    base_size,
                    AILCodeLocation.make_extern(0),
                )
                self.state.stackvar_defs[full_offset] = {pending_def}
        else:
            self.state.stackvar_defs[full_offset] = defs

        return self.state.live_stackvars[offset]

    def stackvar_set(self, base_offset: int, extra_offset: int, base_size: int, value: Value):
        if extra_offset > 1 << (self.project.arch.bits - 1):
            extra_offset -= 1 << self.project.arch.bits
        offset = base_offset + min(extra_offset, 0)
        var_offset = max(extra_offset, 0)
        size = var_offset + base_size
        end_offset = offset + size

        self.state.pending_ptr_defines_nonlocal_live.discard(base_offset)
        if base_offset in self.pending_ptr_defines_nonlocal:
            self.pending_ptr_defines_nonlocal[base_offset][2].add((offset, size))

        self.state.live_stackvars[offset] = value

        other_defs: set[Def] = set()
        liveish_defs: set[Def] = set()
        secret_stash: defaultdict[int, set[Def]] = defaultdict(set)
        reached_fixedpoint = False
        while not reached_fixedpoint:
            reached_fixedpoint = True
            for suboff in range(offset, end_offset):
                secret_stash[suboff].update(self.state.stackvar_defs.pop(suboff, set()))
                old_defs = secret_stash[suboff]
                # set up current var mapping
                self.state.stackvar_bases[suboff] = (offset, size)
                other_defs.update(old_defs)
                # additional consideration: if this def only provides values for some bytes,
                # make sure the implicated but not overwritten defs are unified
                if not base_offset + extra_offset <= suboff < base_offset + extra_offset + base_size:
                    liveish_defs.update(old_defs)
                    for old_def in old_defs:
                        definfo = self.def_info[old_def]
                        old_offset = definfo.variable_offset
                        old_end_offset = definfo.variable_endoffset

                        new_offset = min(old_offset, offset)
                        new_end_offset = max(old_end_offset, end_offset)

                        definfo.variable_offset = new_offset
                        definfo.variable_size = new_end_offset - new_offset

                        if offset != new_offset:
                            offset = new_offset
                            reached_fixedpoint = False
                        if end_offset != new_end_offset:
                            end_offset = new_end_offset
                            reached_fixedpoint = False
                        size = offset - end_offset

        loc2, def2 = self.state.pending_ptr_defines.pop(base_offset, (None, None))
        if loc2 is not None:
            assert def2 is not None
            self.perform_def("stack", def2, offset, size, base_offset + extra_offset, base_size, loc2, other_defs)
            self.state.stackvar_defs[offset] = {def2} | liveish_defs

    def register_get(self, offset: int, size: int, def_: Def) -> Value:
        full_offset, full_size, popped = self.state.register_unify(offset, size)

        secret_stash = defaultdict(set)
        while True:  # this loop should run until the UH OH is never reached
            for popped_offset in popped:
                secret_stash[popped_offset].update(self.state.register_defs.pop(popped_offset, set()))
                for def2 in secret_stash[popped_offset]:
                    self.state.register_defs[full_offset].add(def2)
                    definfo = self.def_info[def2]
                    if definfo.variable_offset < full_offset or definfo.variable_endoffset > full_offset + full_size:
                        # UH OH. We have information from a parallel timeline about how big this var actually is...
                        full_offset, full_size, popped2 = self.state.register_unify(
                            definfo.variable_offset, definfo.variable_size
                        )
                        popped.update(popped2)
                        break
                    definfo.variable_offset = full_offset
                    definfo.variable_size = full_size
                else:
                    continue
                break
            else:
                break

        defs = secret_stash.get(full_offset, set())
        if not defs or full_offset in self.state.register_blackout:
            self.perform_def(
                "reg",
                def_,
                full_offset,
                full_size,
                offset,
                size,
                AILCodeLocation.make_extern(0) if full_offset not in self.state.register_blackout else None,
            )
            self.state.register_defs[full_offset] = {def_}
            self.state.register_blackout.discard(full_offset)
        else:
            self.state.register_defs[full_offset] = defs

        return self.state.live_registers[offset]

    def register_set(self, offset: int, size: int, value: Value, def_: Def):
        self.state.live_registers[offset] = value

        for suboff in range(offset, offset + size):
            self.state.register_defs.pop(suboff, None)
            self.state.register_bases[suboff] = (offset, size)

        self.state.register_defs[offset] = {def_}
        self.perform_def("reg", def_, offset, size, offset, size)
        self.state.register_blackout.discard(offset)

    def _handle_stmt_Assignment(self, stmt):
        src = self._expr(stmt.src)

        if isinstance(stmt.dst, Register):
            self.register_set(stmt.dst.reg_offset, stmt.dst.size, src, stmt.dst)
        elif isinstance(stmt.dst, VirtualVariable):
            self.state.live_vvars[stmt.dst.varid] = src
        elif isinstance(stmt.dst, Tmp):
            self.state.live_tmps[stmt.dst.tmp_idx] = src

    def _handle_stmt_WeakAssignment(self, stmt):
        self._expr(stmt.src)
        self._expr(stmt.dst)

    def _handle_stmt_CAS(self, stmt: CAS):
        self._expr(stmt.addr)
        self._expr(stmt.data_lo)
        if stmt.data_hi is not None:
            self._expr(stmt.data_hi)
        self._expr(stmt.expd_lo)
        if stmt.expd_hi is not None:
            self._expr(stmt.expd_hi)

    def _handle_stmt_Store(self, stmt: Store):
        src = self._expr(stmt.data)
        if stmt.guard is not None:
            self._expr(stmt.guard)

        addr = self._expr(stmt.addr)

        if self.stackvars:
            for stackoff, extra in addr:
                if stackoff is not None:
                    self.stackvar_set(stackoff, extra, stmt.data.size, src)

    def _handle_stmt_ConditionalJump(self, stmt: ConditionalJump):
        self._expr(stmt.condition)
        if stmt.true_target is not None:
            self._expr(stmt.true_target)
        if stmt.false_target is not None:
            self._expr(stmt.false_target)

        if isinstance(stmt.true_target, Const) and stmt.true_target.value != self.ins_addr:
            self.hclb_side_exit_state = self.state.copy()
        if isinstance(stmt.false_target, Const) and stmt.false_target.value != self.ins_addr:
            self.hclb_side_exit_state = self.state.copy()

    def _handle_stmt_Call(self, stmt: Call):
        result = self._handle_expr_Call(stmt)

        if stmt.ret_expr is not None and isinstance(stmt.ret_expr, Register):
            self.register_set(stmt.ret_expr.reg_offset, stmt.ret_expr.size, result, stmt.ret_expr)
        if stmt.fp_ret_expr is not None and isinstance(stmt.fp_ret_expr, Register):
            self.register_set(stmt.fp_ret_expr.reg_offset, stmt.fp_ret_expr.size, result, stmt.fp_ret_expr)

    def _handle_expr_Call(self, expr):
        target = expr.target

        def_size = None
        def_size_arg = None
        if target == "memset":
            # TODO other intrinsics that do a def
            assert expr.args is not None
            def_size_values = self._expr(expr.args[2])
            if len(def_size_values) == 1 and max(def_size_values)[0] is None:
                def_size = max(def_size_values)[1]
                def_size_arg = expr.args[2]

        if isinstance(target, Const) and isinstance(target.value, int):
            target = target.value
        target = self.functions(target) if self.functions is not None and isinstance(target, (str, int)) else None
        if expr.prototype is not None:
            proto = expr.prototype
        elif target is not None and target.prototype is not None:
            proto = target.prototype
        else:
            proto = None

        if proto is not None:
            for ty, argexpr in zip(proto.args, expr.args or []):
                if argexpr is def_size_arg:
                    assert def_size is not None
                    value = {(None, def_size)}
                else:
                    value = self._expr(argexpr)

                if not value:
                    continue

                if not isinstance(ty, SimTypePointer):
                    continue
                if ty.disposition == PointerDisposition.OUT:
                    outptr = True
                elif ty.disposition in (PointerDisposition.NONE, PointerDisposition.UNKNOWN):
                    continue
                else:
                    outptr = False

                if outptr and def_size is not None:
                    size = def_size
                else:
                    if ty.pts_to is None:
                        size = 1
                    else:
                        size = (ty.pts_to.size or 8) // 8
                        if not size:
                            continue

                for stackref, extra in value:
                    if stackref is not None:
                        if outptr:
                            self.stackvar_set(stackref, extra, size, set())
                        else:
                            self.stackvar_get(stackref, extra, size)
        else:
            for argexpr in expr.args or []:
                self._expr(argexpr)

        # kill caller-saved registers
        if expr.calling_convention is not None:
            cc = expr.calling_convention
        elif target is not None and target.calling_convention is not None:
            cc = target.calling_convention
        else:
            cc = default_cc(self.arch.name, platform=self.simos.name if self.simos is not None else None)
            assert cc is not None
            cc = cc(self.arch)

        for reg_name in cc.CALLER_SAVED_REGS:
            reg_offset = self.arch.registers[reg_name][0]
            base_off = get_reg_offset_base(reg_offset, self.arch)
            self.state.live_registers.pop(base_off, None)
            self.state.register_defs.pop(base_off, None)
            self.state.register_blackout.add(base_off)
        for reg in cc.arch.vex_cc_regs or []:
            self.state.live_registers.pop(reg.vex_offset, None)
            self.state.register_defs.pop(reg.vex_offset, None)
            self.state.register_blackout.add(reg.vex_offset)

        return set()

    def _handle_stmt_Dummy(self, stmt):
        pass

    def _handle_stmt_DirtyStatement(self, stmt):
        self._expr(stmt.dirty)

    def _handle_stmt_Jump(self, stmt):
        self._expr(stmt.target)

    _handle_stmt_Label = _handle_stmt_Dummy

    def _handle_stmt_Return(self, stmt):
        for expr in stmt.ret_exprs:
            self._expr(expr)

    def _handle_expr_VirtualVariable(self, expr):
        return self.state.live_vvars[expr.varid]

    def _handle_expr_Register(self, expr: Register):
        return self.register_get(expr.reg_offset, expr.size, expr)

    def _handle_expr_Load(self, expr: Load):
        addr = self._expr(expr.addr)
        result = set()
        if self.stackvars:
            for offset, extra in addr:
                if offset is None:
                    continue
                result.update(self.stackvar_get(offset, extra, expr.size))
        return result

    def _handle_expr_StackBaseOffset(self, expr: StackBaseOffset) -> Value:
        if not self.stackvars:
            return set()
        if not isinstance(expr.offset, int):
            return set()

        if expr.offset not in self.state.pending_ptr_defines:
            self.state.pending_ptr_defines[expr.offset] = (self._acodeloc(), expr)
            # if this is the first time we've ever seen anything resembling this stackvar,
            # force this to be a def. otherwise, track future uses of this reference.
            # if we get to the end of the block and we haven't seen it used yet,
            # we'll require no more reads-before-writes in the rest of the function
            # to call this a new def
            if expr.offset not in self.state.stackvar_bases:
                self.stackvar_get(expr.offset, 0, 1)
                self.state.pending_ptr_defines[expr.offset] = (self._acodeloc(), expr)

        return {(expr.offset, 0)}

    def _handle_expr_Tmp(self, expr: Tmp):
        return self.state.live_tmps[expr.tmp_idx]

    def _handle_expr_Const(self, expr) -> Value:
        if isinstance(expr.value, int):
            return {(None, expr.value)}
        return set()

    def _handle_expr_Convert(self, expr: Convert) -> Value:
        val = self._expr(expr.operand)
        result = set()
        for off, v in val:
            if off is not None:
                continue
            if expr.is_signed and v > 1 << (expr.from_bits - 1):
                v -= 1 << expr.from_bits
            result.add((None, v))
        return result

    def _handle_expr_Reinterpret(self, expr) -> Value:
        self._expr(expr.operand)
        return set()

    def _handle_expr_UnaryOp(self, expr) -> Value:
        self._expr(expr.operand)
        return set()

    def _handle_expr_BinaryOp(self, expr) -> Value:
        a0 = self._expr(expr.operands[0])
        a1 = self._expr(expr.operands[1])

        if expr.op == "Add":
            sign = 1
        elif expr.op == "Sub":
            sign = -1
        else:
            return set()

        result: Value = set()
        for arg0 in a0:
            for arg1 in a1:
                if (arg0[0] is None or arg1[0] is None) and (arg0[1] is not None and arg1[1] is not None):
                    result.add((arg0[0] or arg1[0], arg0[1] + sign * arg1[1]))
        if len(result) > CUTOFF:
            result = set(sorted(result, key=offset_sort_key)[:CUTOFF])
        return result

    def _handle_expr_Phi(self, expr) -> Value:
        result = set()
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                result.update(self._expr(vvar))
        if len(result) > CUTOFF:
            result = set(sorted(result, key=offset_sort_key)[:CUTOFF])
        return result

    def _handle_expr_ITE(self, expr: ITE):
        self._expr(expr.cond)
        self._expr(expr.iftrue)
        self._expr(expr.iffalse)
        return set()

    def _handle_expr_VEXCCallExpression(self, expr: VEXCCallExpression):
        for operand in expr.operands:
            self._expr(operand)
        return set()

    def _handle_expr_DirtyExpression(self, expr: DirtyExpression):
        for operand in expr.operands:
            self._expr(operand)
        if expr.guard is not None:
            self._expr(expr.guard)
        if expr.maddr is not None:
            self._expr(expr.maddr)
        return set()

    def _handle_expr_Extract(self, expr: Extract):
        self._expr(expr.base)
        self._expr(expr.offset)
        return set()

    def _handle_expr_Insert(self, expr: Insert):
        self._expr(expr.base)
        self._expr(expr.offset)
        self._expr(expr.value)
        return set()

    def _handle_expr_MultiStatementExpression(self, expr) -> Value:
        return set()

    def _handle_expr_BasePointerOffset(self, expr) -> Value:
        return set()

    def _unreachable(self, *args, **kwargs):
        assert False, "unreachable"

    _handle_binop_CmpLE = _unreachable
    _handle_binop_CmpLT = _unreachable
    _handle_binop_CmpGE = _unreachable
    _handle_binop_CmpGT = _unreachable
    _handle_binop_CmpEQ = _unreachable
    _handle_binop_CmpNE = _unreachable
    _handle_binop_CmpORD = _unreachable
    _handle_binop_Add = _unreachable
    _handle_binop_AddF = _unreachable
    _handle_binop_AddV = _unreachable
    _handle_binop_And = _unreachable
    _handle_binop_Carry = _unreachable
    _handle_binop_CmpF = _unreachable
    _handle_binop_Concat = _unreachable
    _handle_binop_Div = _unreachable
    _handle_binop_DivF = _unreachable
    _handle_binop_DivV = _unreachable
    _handle_binop_LogicalAnd = _unreachable
    _handle_binop_LogicalOr = _unreachable
    _handle_binop_Mod = _unreachable
    _handle_binop_Mul = _unreachable
    _handle_binop_Mull = _unreachable
    _handle_binop_MulF = _unreachable
    _handle_binop_MulV = _unreachable
    _handle_binop_MulHiV = _unreachable
    _handle_binop_Or = _unreachable
    _handle_binop_Rol = _unreachable
    _handle_binop_Ror = _unreachable
    _handle_binop_SBorrow = _unreachable
    _handle_binop_SCarry = _unreachable
    _handle_binop_Sar = _unreachable
    _handle_binop_Shl = _unreachable
    _handle_binop_Shr = _unreachable
    _handle_binop_Sub = _unreachable
    _handle_binop_SubF = _unreachable
    _handle_binop_SubV = _unreachable
    _handle_binop_Xor = _unreachable
    _handle_binop_InterleaveLOV = _unreachable
    _handle_binop_InterleaveHIV = _unreachable
    _handle_binop_CasCmpEQ = _unreachable
    _handle_binop_CasCmpNE = _unreachable
    _handle_binop_ExpCmpNE = _unreachable
    _handle_binop_SarNV = _unreachable
    _handle_binop_ShrNV = _unreachable
    _handle_binop_ShlNV = _unreachable
    _handle_binop_CmpEQV = _unreachable
    _handle_binop_CmpNEV = _unreachable
    _handle_binop_CmpGEV = _unreachable
    _handle_binop_CmpGTV = _unreachable
    _handle_binop_CmpLEV = _unreachable
    _handle_binop_CmpLTV = _unreachable
    _handle_binop_MinV = _unreachable
    _handle_binop_MaxV = _unreachable
    _handle_binop_QAddV = _unreachable
    _handle_binop_QNarrowBinV = _unreachable
    _handle_binop_PermV = _unreachable
    _handle_binop_Set = _unreachable

    _handle_unop_BitwiseNeg = _unreachable
    _handle_unop_Dereference = _unreachable
    _handle_unop_Neg = _unreachable
    _handle_unop_Not = _unreachable
    _handle_unop_Reference = _unreachable
    _handle_unop_Clz = _unreachable
    _handle_unop_Ctz = _unreachable
    _handle_unop_GetMSBs = _unreachable
    _handle_unop_unpack = _unreachable
    _handle_unop_Sqrt = _unreachable
    _handle_unop_RSqrtEst = _unreachable
