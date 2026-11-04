from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from itertools import chain, count
from typing import TYPE_CHECKING, cast

from angr.ailment.expression import (
    ITE,
    ComboRegister,
    Const,
    Convert,
    DirtyExpression,
    Expression,
    Extract,
    Insert,
    IRegister,
    Load,
    Register,
    StackBaseOffset,
    Tmp,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.ailment.statement import CAS, ConditionalJump, SideEffectStatement, Store
from angr.calling_conventions import call_clobbered_regs, default_cc_for_project
from angr.code_location import AILCodeLocation
from angr.engines.light import SimEngineLightAIL
from angr.enums import Flavors
from angr.go.sim_type import GoSimTypeFunction
from angr.knowledge_plugins.functions.function import Function
from angr.sim_type import PointerDisposition, SimTypePointer
from angr.utils.ssa import get_reg_offset_base_and_size

from .consts import MAX_STACK_VAR_SIZE
from .traversal_state import TraversalState, Value, has_conflicting_value_types

if TYPE_CHECKING:
    from angr.analyses.decompiler import VariableMap
    from angr.analyses.decompiler.ssailification.ssailification import Def, Kind
    from angr.calling_conventions import SimCC
    from angr.project import Project

FRAME_LOW_SLACK = 0x1000
CUTOFF = 15  # arbitrary; be mindful of performance as various parts will be O(N^2)


def offset_sort_key(v: tuple[int | None, int]) -> tuple[int, int, int, int]:
    # used for iterating over Value in a determinisitic order
    # moderately arbitrary. feel free to change as long as
    # - it produces a total ordering, i.e. f(a) == f(b) iff a == b
    # - it never returns None values, as these cannot be sorted
    return (v[1], 0 if v[0] is not None else 1, abs(v[0] or 0), 0 if v[0] is None or v[0] < 0 else 1)


def _has_explicit_variadic_args(proto) -> bool:
    """Go spells its variadic parameter as a slice, so the prototype already lists every argument."""
    return isinstance(proto, GoSimTypeFunction)


@dataclass
class DefInfo:
    """
    Information about a def, or an expression that defines a new SSA variable.
    """

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
        variable_map=None,
        ail_manager=None,
        flavor: str = Flavors.DEFAULT_FLAVOR,
    ):
        super().__init__(project)
        self.simos = simos
        self.flavor = flavor
        self.sp_tracker = sp_tracker
        # no object starts below the deepest stack pointer the function reaches (with a page of slack); a stack
        # "pointer" there is a pointer difference such as &buf - &global
        self.frame_low: int | None = None
        if stackvars and sp_tracker is not None:
            lowest = sp_tracker.lowest_offset(project.arch.sp_offset)
            if lowest is not None:
                self.frame_low = lowest - FRAME_LOW_SLACK
        self.bp_as_gpr = bp_as_gpr
        self.stackvars = stackvars
        # calls define the stack variables whose addresses escape to them. Not for Go yet: its runtime idiom passes
        # match the single-version shape of the stack slots that runtime calls take the address of.
        self._model_escapes = stackvars and flavor != Flavors.GO_FLAVOR
        self.use_tmps = use_tmps
        self.functions = functions
        self.variable_map: VariableMap | None = variable_map
        self._next_atom = ail_manager.next_atom if ail_manager is not None else count(1 << 30).__next__
        # a call defines every caller-saved register it clobbers. One synthetic Def per (call, base register),
        # created lazily when a clobbered register is read, so reads on every path share the definition.
        self._clobber_defs: dict[tuple[AILCodeLocation, int], Register] = {}
        self.clobber_defs_by_loc: dict[tuple[int, int, int], list[Def]] = defaultdict(list)
        # likewise one synthetic Def per (call, escaped stack offset), for a stack variable read after a call that may
        # have written it through its escaped address
        self._stack_clobber_defs: dict[tuple[AILCodeLocation, int], StackBaseOffset] = {}
        # the defs each (call, escaped offset) ended, so that they keep the extents of the variable
        self._stack_clobbered_defs: dict[tuple[AILCodeLocation, int], set[Def]] = {}
        self._stack_clobber_keys: dict[Def, tuple[AILCodeLocation, int]] = {}
        # the bytes [lo, hi) each (call, escaped offset) may access
        self._stack_clobber_reach: dict[tuple[AILCodeLocation, int], tuple[int, int]] = {}
        # sorted frame offsets whose address the function takes; a callee given a frame address reaches up to the next
        # one (the convention of variadic_call_reads)
        self.taken_offsets: list[int] = []
        self.def_info: dict[Def, DefInfo] = {}
        # stack offset -> code location, StackBaseOffset expr, set of (offset, size) tuples, required, no_reaching_def
        self.pending_ptr_defines_nonlocal: dict[
            int, tuple[AILCodeLocation, StackBaseOffset, set[tuple[int, int]], bool, bool]
        ] = {}
        # the state which skipped the last few statements; the state that breaks the loop
        self.hclb_side_exit_state: TraversalState | None = None

    def _is_top(self, expr):
        return not expr

    def _top(self, bits):
        return set()

    def _process_block_end(self, block, stmt_data, whitelist):
        # see comment in StackBaseOffset handler
        for k, lst in self.state.pending_ptr_defines.items():
            v1, v2 = lst[0]
            if k not in self.pending_ptr_defines_nonlocal:
                # make sure the pending pointer def has a definition of its own
                no_reaching_def = k not in self.state.stackvar_defs and k not in self.state.stack_blackout
                required = k not in self.state.live_stackvars or no_reaching_def
                self.pending_ptr_defines_nonlocal[k] = v1, v2, set(), required, no_reaching_def
                self.state.pending_ptr_defines_nonlocal_live.add(k)
        self.state.pending_ptr_defines.clear()  # just in case

    def finalize(self):
        for stack_offset, (
            loc,
            def_,
            suggestions,
            required,
            no_reaching_def,
        ) in self.pending_ptr_defines_nonlocal.items():
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
                AILCodeLocation.make_extern(0) if no_reaching_def else loc,
            )

        # sketchy situation. we want to make sure everything in the extern set
        # has exactly the same extents if they overlap at all. this is sorta a redo
        # of the unify code.
        # group overlapping extern defs per kind by sweeping them in start order
        extern_defs: dict[str, list[DefInfo]] = {"reg": [], "stack": []}
        for definfo in self.def_info.values():
            if not definfo.loc.is_extern:
                continue
            if definfo.kind not in extern_defs:
                raise ValueError(f"Unsupported def kind {definfo.kind} in finalize")
            if definfo.variable_size > 0:
                extern_defs[definfo.kind].append(definfo)

        for definfos in extern_defs.values():
            definfos.sort(key=lambda di: di.variable_offset)
            current_extent = (0, 0)
            current_defs = set()
            for definfo in definfos:
                if definfo.variable_offset >= current_extent[1] or current_extent[0] == current_extent[1]:
                    self._flush(current_defs, current_extent)
                    current_defs.clear()
                    current_extent = definfo.variable_offset, definfo.variable_endoffset

                current_defs.add(definfo.def_)
                current_extent = (
                    min(current_extent[0], definfo.variable_offset),
                    max(current_extent[1], definfo.variable_endoffset),
                )

            self._flush(current_defs, current_extent)

    def _flush(self, current_defs: set[Def], current_extent: tuple[int, int]) -> None:
        for def2 in current_defs:
            definfo = self.def_info[def2]
            size2 = current_extent[1] - current_extent[0]
            definfo.variable_offset = current_extent[0]
            definfo.variable_size = size2

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
            loc.is_extern
            or def_ not in self.def_info
            or self.def_info[def_].loc == loc
            or self.def_info[def_].loc.is_extern
        ), "claiming an expression defines at two different locs"
        # re-traversing a block re-defines its extern defs; keep the extents widened by later reads
        if (definfo := self.def_info.get(def_)) is None or (definfo.loc.is_extern and not loc.is_extern):
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
        else:
            end_offset = definfo.variable_endoffset
            definfo.variable_offset = min(definfo.variable_offset, variable_offset)
            new_end_offset = max(end_offset, variable_offset + variable_size)
            definfo.variable_size = new_end_offset - definfo.variable_offset

        return definfo

    def _out_of_frame_base(self, base_offset: int, extra_offset: int) -> bool:
        # the base lies below the frame but the access lands inside it: address the accessed bytes directly
        return (
            extra_offset != 0
            and self.frame_low is not None
            and base_offset < self.frame_low <= base_offset + extra_offset
        )

    def stackvar_get(self, base_offset: int, extra_offset: int, base_size: int) -> Value:
        if extra_offset > 1 << (self.project.arch.bits - 1):
            extra_offset -= 1 << self.project.arch.bits
        if extra_offset < 0 and base_offset == -self.project.arch.bytes:
            # a negative offset from the saved-frame-pointer slot (rbp = sp-8 after the prologue) addresses a local,
            # not an object that starts at the base; treat it as a plain access at the concrete address. pointers
            # into the middle of a stack array (p = &arr[1]; p[-1]) must keep extending the array backwards.
            return self.stackvar_get(base_offset + extra_offset, 0, base_size)
        if self._out_of_frame_base(base_offset, extra_offset):
            return self.stackvar_get(base_offset + extra_offset, 0, base_size)
        concrete_offset = base_offset + extra_offset
        offset = min(concrete_offset, base_offset)
        end_offset = max(concrete_offset, base_offset) + base_size
        size = end_offset - offset
        if size >= MAX_STACK_VAR_SIZE:
            return set()

        full_offset, full_size, _ = self.state.stackvar_unify(offset, size)

        if base_offset in self.state.pending_ptr_defines_nonlocal_live:
            self.pending_ptr_defines_nonlocal.pop(base_offset, None)

        lst = self.state.pending_ptr_defines.pop(base_offset, [])
        pending_def = cast("Def", lst[-1][1]) if lst else None
        stackvar_defs = self.state.stackvar_defs
        # Merging states unions stackvar_defs and stackvar_bases per byte, so a def may only be recorded on the
        # bytes it stored, not on the (merged) base offset of its variable. Collect defs from every byte of the
        # unified range so that all of them get widened to the full variable.
        defs: set[Def] = set()
        # defs a call ended; they no longer reach, but they still name this variable
        superseded: set[Def] = set()
        while True:  # this loop should run until the UH OH is never reached
            self._materialize_stack_clobbers(full_offset, full_offset + full_size)
            for _, _, seg_defs in stackvar_defs.pop_range(full_offset, full_offset + full_size):
                defs.update(seg_defs)
            superseded = self._superseded_by(defs)
            for def2 in chain(defs, superseded):
                definfo = self.def_info[def2]
                if definfo.variable_offset < full_offset or definfo.variable_endoffset > full_offset + full_size:
                    # UH OH. We have information from a parallel timeline about how big this var actually is...
                    newish_offset = min(definfo.variable_offset, full_offset)
                    newish_endoffset = max(definfo.variable_endoffset, full_offset + full_size)
                    full_offset, full_size, _ = self.state.stackvar_unify(
                        newish_offset, newish_endoffset - newish_offset
                    )
                    break
            else:
                break
        for def2 in chain(defs, superseded):
            definfo = self.def_info[def2]
            definfo.variable_offset = full_offset
            definfo.variable_size = full_size

        def_as = None
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
                def_as = {pending_def}
        else:
            def_as = defs

        if def_as is not None:
            stackvar_defs.assign(full_offset, full_offset + full_size, def_as)

        return (
            self.state.live_stackvars[offset]
            if not has_conflicting_value_types(self.state.live_stackvars[offset])
            else set()
        )

    def stackvar_set(self, base_offset: int, extra_offset: int, base_size: int, value: Value):
        if extra_offset > 1 << (self.project.arch.bits - 1):
            extra_offset -= 1 << self.project.arch.bits
        if extra_offset < 0 and base_offset == -self.project.arch.bytes:
            # see stackvar_get
            self.stackvar_set(base_offset + extra_offset, 0, base_size, value)
            return
        if self._out_of_frame_base(base_offset, extra_offset):
            self.stackvar_set(base_offset + extra_offset, 0, base_size, value)
            return
        concrete_offset = base_offset + extra_offset
        offset = min(concrete_offset, base_offset)
        end_offset = max(concrete_offset, base_offset) + base_size
        size = end_offset - offset

        if size >= MAX_STACK_VAR_SIZE:
            return

        self.state.pending_ptr_defines_nonlocal_live.discard(base_offset)
        if base_offset in self.pending_ptr_defines_nonlocal:
            self.pending_ptr_defines_nonlocal[base_offset][2].add((offset, size))

        self.state.live_stackvars = self.state.live_stackvars.clean()
        self.state.live_stackvars[offset] = value
        store_offset = base_offset + extra_offset
        store_end_offset = store_offset + base_size
        if any(
            lo < store_offset or hi > store_end_offset
            for lo, hi, _ in self.state.stack_blackout.overlapping(offset, end_offset)
        ):
            # the bytes this store does not overwrite hold what the call wrote
            self._materialize_stack_clobbers(offset, end_offset)
        self.state.stack_blackout.pop_range(offset, end_offset)
        stackvar_defs = self.state.stackvar_defs
        other_defs: set[Def] = set()
        # defs of bytes this store does not overwrite; they get unified with the stored-to variable
        liveish_defs: set[Def] = set()
        popped_lo = popped_hi = offset
        reached_fixedpoint = False
        while not reached_fixedpoint:
            reached_fixedpoint = True
            if popped_lo == popped_hi:
                old_segs = stackvar_defs.pop_range(offset, end_offset)
            else:
                old_segs = stackvar_defs.pop_range(offset, popped_lo) + stackvar_defs.pop_range(popped_hi, end_offset)
            popped_lo, popped_hi = offset, end_offset
            for seg_lo, seg_hi, old_defs in old_segs:
                other_defs.update(old_defs)
                if seg_lo < store_offset or seg_hi > store_end_offset:
                    liveish_defs.update(old_defs)
            for old_def in chain(liveish_defs, self._superseded_by(liveish_defs)):
                definfo = self.def_info[old_def]
                new_offset = min(definfo.variable_offset, offset)
                new_end_offset = max(definfo.variable_endoffset, end_offset)
                definfo.variable_offset = new_offset
                definfo.variable_size = new_end_offset - new_offset
                if offset != new_offset or end_offset != new_end_offset:
                    offset, end_offset = new_offset, new_end_offset
                    reached_fixedpoint = False
        size = end_offset - offset
        self.state.stackvar_bases.assign(offset, end_offset, (offset, size))

        loc2, def2 = self.state.pending_ptr_defines.pop(base_offset, [(None, None)])[-1]
        def_as = None
        if loc2 is not None:
            assert def2 is not None
            self.perform_def("stack", def2, offset, size, base_offset + extra_offset, base_size, loc2, other_defs)
            def_as = {def2} | liveish_defs

        if def_as is not None:
            stackvar_defs.assign(offset, end_offset, def_as)

    def register_get(self, offset: int, size: int, def_: Def | None) -> Value:
        full_offset, full_size, popped = self.state.register_unify(offset, size)

        secret_stash: defaultdict[int, set[Def]] = defaultdict(set)
        while True:  # this loop should run until the UH OH is never reached
            for popped_offset in popped:
                secret_stash[popped_offset].update(self.state.register_defs.pop(popped_offset, set()))
                for def2 in secret_stash[popped_offset]:
                    self.state.register_defs[full_offset].add(def2)
                    definfo = self.def_info[def2]
                    if definfo.variable_offset < full_offset or definfo.variable_endoffset > full_offset + full_size:
                        # UH OH. We have information from a parallel timeline about how big this var actually is...
                        newish_offset = min(definfo.variable_offset, full_offset)
                        newish_endoffset = max(definfo.variable_endoffset, full_offset + full_size)
                        full_offset, full_size, popped2 = self.state.register_unify(
                            newish_offset, newish_endoffset - newish_offset
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

        defs: set[Def] = set().union(*secret_stash.values())
        clobber_locs = self.state.register_blackout.get(full_offset)
        def_as = None
        if clobber_locs:
            # define the clobbered registers
            def_as = set(defs)
            for loc in sorted(
                clobber_locs, key=lambda loc: (loc.addr, -1 if loc.block_idx is None else loc.block_idx, loc.stmt_idx)
            ):
                clobber_def = self._clobber_def(loc, full_offset, full_size)
                self.perform_def("reg", clobber_def, full_offset, full_size, offset, size, loc)
                def_as.add(clobber_def)
            for suboff in range(full_offset, full_offset + full_size):
                self.state.register_blackout.pop(suboff, None)
        elif not defs:
            assert def_ is not None, "register_get() requires def_, but no definition reaches this point"
            self.perform_def("reg", def_, full_offset, full_size, offset, size, AILCodeLocation.make_extern(0))
            def_as = {def_}
        else:
            def_as = defs

        if def_as is not None:
            for suboff in range(full_offset, full_offset + full_size):
                self.state.register_defs[suboff] = def_as

        return (
            self.state.live_registers[offset]
            if not has_conflicting_value_types(self.state.live_registers[offset])
            else set()
        )

    def clobber_def_for(self, loc: AILCodeLocation, reg_offset: int) -> Register | None:
        """
        The definition that the call at ``loc`` created for the register containing ``reg_offset``, if a read of that
        register ever reached back to this call.
        """
        base_off, _ = get_reg_offset_base_and_size(reg_offset, self.project.arch)
        return self._clobber_defs.get((loc, base_off))

    def _clobber_def(self, loc: AILCodeLocation, full_offset: int, full_size: int) -> Register:
        base_off, _ = get_reg_offset_base_and_size(full_offset, self.project.arch)
        key = (loc, base_off)
        cdef = self._clobber_defs.get(key)
        if cdef is None:
            cdef = Register(self._next_atom(), full_offset, full_size * self.project.arch.byte_width, clobber=True)
            self._clobber_defs[key] = cdef
            self.clobber_defs_by_loc[(loc.addr, loc.block_idx, loc.stmt_idx)].append(cdef)
        return cdef

    @property
    def stack_clobber_defs(self) -> set[Def]:
        """The definitions calls created for escaped stack variables they may write."""
        return set(self._stack_clobber_keys)

    @property
    def stack_clobber_reach(self) -> dict[Def, tuple[int, int]]:
        """The bytes [lo, hi) that the call behind each stack clobber definition may access."""
        return {
            cdef: reach
            for cdef, key in self._stack_clobber_keys.items()
            if (reach := self._stack_clobber_reach.get(key)) is not None
        }

    def _callee_object(self, off: int) -> tuple[int | None, int | None]:
        """
        The bounds of the stack object a callee given the frame address ``off`` reaches: from the closest taken address
        at or below it up to the next one above it (None where there is none).
        """
        taken = self.taken_offsets
        i = bisect_right(taken, off)
        lo = taken[i - 1] if i > 0 else None
        j = bisect_left(taken, off + 1)
        hi = taken[j] if j < len(taken) else None
        return lo, hi

    def stack_clobber_def_for(self, loc: AILCodeLocation, escaped_offset: int) -> StackBaseOffset | None:
        """
        The definition that the call at ``loc`` created for the escaped stack variable at ``escaped_offset``, if a read
        of that variable ever reached back to this call.
        """
        return self._stack_clobber_defs.get((loc, escaped_offset))

    def _superseded_by(self, defs: Iterable[Def]) -> set[Def]:
        """The defs that the call writes among ``defs`` ended, transitively: they still name the same variable."""
        out: set[Def] = set()
        work = [d for d in defs if d in self._stack_clobber_keys]
        while work:
            for old in self._stack_clobbered_defs.get(self._stack_clobber_keys[work.pop()], ()):
                if old not in out:
                    out.add(old)
                    if old in self._stack_clobber_keys:
                        work.append(old)
        return out

    def _unify_clobber_extents(self, cdef: Def) -> None:
        """A call's definition and the defs it ended (transitively) describe one variable: give them one extent."""
        group = [cdef, *self._superseded_by((cdef,))]
        infos = [self.def_info[d] for d in group if d in self.def_info]
        lo = min(di.variable_offset for di in infos)
        hi = max(di.variable_endoffset for di in infos)
        for di in infos:
            di.variable_offset = lo
            di.variable_size = hi - lo

    def _materialize_stack_clobbers(self, lo: int, hi: int) -> None:
        """Turn the call writes that may reach bytes [lo, hi) into definitions of those bytes."""
        segs = self.state.stack_blackout.pop_range(lo, hi)
        if not segs:
            return
        stackvar_defs = self.state.stackvar_defs
        for slo, shi, keys in segs:
            cdefs: set[Def] = set()
            for loc, escaped_offset in sorted(
                keys, key=lambda k: (k[0].addr, -1 if k[0].block_idx is None else k[0].block_idx, k[0].stmt_idx, k[1])
            ):
                key = loc, escaped_offset
                cdef = self._stack_clobber_defs.get(key)
                if cdef is None:
                    cdef = StackBaseOffset(self._next_atom(), self.project.arch.bits, escaped_offset)
                    self._stack_clobber_defs[key] = cdef
                    self._stack_clobber_keys[cdef] = key
                    self.clobber_defs_by_loc[(loc.addr, loc.block_idx, loc.stmt_idx)].append(cdef)
                self.perform_def("stack", cdef, slo, shi - slo, slo, shi - slo, loc)
                self._unify_clobber_extents(cdef)
                cdefs.add(cdef)
            cur = slo
            for dlo, dhi, dst in list(stackvar_defs.overlapping(slo, shi)):
                dlo, dhi = max(dlo, slo), min(dhi, shi)
                if cur < dlo:
                    stackvar_defs.assign(cur, dlo, set(cdefs))
                stackvar_defs.assign(dlo, dhi, dst | cdefs)
                cur = dhi
            if cur < shi:
                stackvar_defs.assign(cur, shi, set(cdefs))

    def _escaped_offsets(self, values: Iterable[Value], through_only: bool = False) -> set[int]:
        """
        Stack offsets that the stack addresses in ``values`` reach, also through a pointer held in such a slot. With
        ``through_only``, only the slots reached through held pointers.
        """
        out: set[int] = set()
        seen: set[int] = set()
        work = [(v, through_only) for value in values for v in value]
        while work:
            (stackref, extra), skip = work.pop()
            if stackref is None:
                continue
            if extra > 1 << (self.project.arch.bits - 1):
                extra -= 1 << self.project.arch.bits
            for off in (stackref, stackref + extra):
                if off in seen or abs(off - stackref) >= MAX_STACK_VAR_SIZE:
                    continue
                seen.add(off)
                if not skip:
                    out.add(off)
                held = self.state.live_stackvars.get(off)
                if held:
                    work.extend((v, False) for v in held)
        return out

    def _clobber_escaped_stackvars(self, call_loc: AILCodeLocation, passed: set[int], written: set[int]) -> None:
        """
        A call may write the stack variables whose addresses it is given: their reaching defs end here. (A call that
        is not given the address may still write through a copy kept elsewhere; SPropagator keeps reads of such slots
        from moving across calls, but their SSA versions do not change there.)
        """
        # references in this call's arguments that already define their variable here
        own_refs = {expr for lst in self.state.pending_ptr_defines.values() for loc, expr in lst if loc == call_loc}
        for off in sorted(passed):
            if off in written:
                # the call's own out-pointer definition
                continue
            lo, size = self.state.stackvar_bases.get(off, (off, 1))
            if size <= 0:
                lo, size = off, 1
            hi = lo + size
            # the callee reaches only the object at the address it is given, even where stack SSA made one variable of
            # several objects (a VM frame)
            obj_lo, obj_hi = self._callee_object(off)
            if obj_lo is None:
                obj_lo = -(1 << self.project.arch.bits)
            if obj_hi is None:
                obj_hi = 1 << self.project.arch.bits
            lo, hi = max(lo, obj_lo), min(hi, obj_hi)
            reaching = set().union(*(d for _, _, d in self.state.stackvar_defs.overlapping(lo, hi)))
            # bytes an earlier call may have written (not yet turned into a def) hold a value this call may replace
            written_before = list(self.state.stack_blackout.overlapping(lo, hi))
            if reaching <= own_refs and not written_before:
                # nothing defined before the call reaches it, so no stale value is left
                continue
            # the call's definition covers the variable the ended defs describe, within the object
            for d in reaching:
                definfo = self.def_info[d]
                lo, hi = min(lo, definfo.variable_offset), max(hi, definfo.variable_endoffset)
            for blo, bhi, _ in written_before:
                lo, hi = min(lo, blo), max(hi, bhi)
            lo, hi = max(lo, obj_lo), min(hi, obj_hi)
            prev = self._stack_clobber_reach.get((call_loc, off))
            self._stack_clobber_reach[(call_loc, off)] = (
                (lo, hi) if prev is None else (min(lo, prev[0]), max(hi, prev[1]))
            )
            # the defs stay in stackvar_defs: they no longer reach a read, but they keep shaping the variable's extent.
            # only the variable the address points into takes the call's definition as a version; another variable in
            # the object keeps its own extent
            ended = self._stack_clobbered_defs.setdefault((call_loc, off), set())
            for _, _, seg_defs in self.state.stackvar_defs.overlapping(lo, hi):
                for d in seg_defs:
                    definfo = self.def_info[d]
                    if definfo.variable_offset <= off < definfo.variable_endoffset:
                        ended.add(d)
            for _, _, keys in written_before:
                # what an earlier call wrote: its definition if one exists, otherwise the defs that call ended
                for key in keys:
                    earlier = self._stack_clobber_defs.get(key)
                    if earlier is not None:
                        ended.add(earlier)
                    else:
                        ended |= self._stack_clobbered_defs.get(key, set())
            cdef = self._stack_clobber_defs.get((call_loc, off))
            if cdef is not None:
                # a later visit of this call: defs that reach it only now name the same variable as its definition
                self._unify_clobber_extents(cdef)
            self.state.stack_blackout.assign(lo, hi, frozenset(((call_loc, off),)))
            # the values (stack addresses) the variable held are no longer known; it stays live
            stale = [k for k in self.state.live_stackvars if lo <= k < hi and self.state.live_stackvars.get(k)]
            if stale:
                self.state.live_stackvars = self.state.live_stackvars.clean()
                for k in stale:
                    self.state.live_stackvars[k] = set()

    def register_set(self, offset: int, size: int, value: Value, def_: Def):
        self.state.live_registers[offset] = value

        for suboff in range(offset, offset + size):
            self.state.register_defs.pop(suboff, None)
            self.state.register_bases[suboff] = (offset, size)
            self.state.register_blackout.pop(suboff, None)

        self.perform_def("reg", def_, offset, size, offset, size)

        for suboff in range(offset, offset + size):
            self.state.register_defs[suboff] = {def_}

    def _handle_stmt_Assignment(self, stmt):
        src = self._expr(stmt.src)

        if isinstance(stmt.dst, Register):
            self.register_set(stmt.dst.reg_offset, stmt.dst.size, src, stmt.dst)
        elif isinstance(stmt.dst, IRegister):
            # Unresolved indexed register write -- resolve if possible, else skip
            offset = stmt.dst.concrete_reg_offset()
            if offset is not None:
                self.register_set(offset, stmt.dst.size, src, stmt.dst)
        elif isinstance(stmt.dst, ComboRegister):
            # a multi-register value defines every constituent register
            for reg in cast("list[Register]", stmt.dst.registers):
                self.register_set(reg.reg_offset, reg.size, src, reg)
        elif isinstance(stmt.dst, VirtualVariable):
            self.state.live_vvars = self.state.live_vvars.clean()
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

        if (
            isinstance(stmt.true_target, Const)
            and isinstance(stmt.false_target, Const)
            and self.stmt_idx != len(self.block.statements) - 1
            and self.ins_addr in (stmt.true_target.value, stmt.false_target.value)
        ):
            self.hclb_side_exit_state = self.state.copy()

    def _handle_stmt_SideEffectStatement(self, stmt: SideEffectStatement):
        result = self._handle_expr_Call(stmt.expr)

        if stmt.ret_expr is not None and isinstance(stmt.ret_expr, Register):
            self.register_set(stmt.ret_expr.reg_offset, stmt.ret_expr.size, result, stmt.ret_expr)
        elif isinstance(stmt.ret_expr, ComboRegister):
            # a multi-register result defines every constituent register
            for reg in stmt.ret_expr.registers:
                assert isinstance(reg, Register)
                self.register_set(reg.reg_offset, reg.size, result, reg)
        if stmt.fp_ret_expr is not None and isinstance(stmt.fp_ret_expr, Register):
            self.register_set(stmt.fp_ret_expr.reg_offset, stmt.fp_ret_expr.size, result, stmt.fp_ret_expr)

    def _handle_expr_Call(self, expr):
        target = expr.target
        if isinstance(target, Expression):
            self._expr(target)

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
        expr_prototype = self.variable_map.prototype(expr) if self.variable_map is not None else None
        if expr_prototype is not None:
            proto = expr_prototype
        elif target is not None and (target_proto := target.get_prototype(self.flavor)) is not None:
            proto = target_proto
        else:
            proto = None

        # values passed to the callee, and the stack offsets the call defines through out-pointers
        arg_values: list[Value] = []
        read_only_values: list[Value] = []
        out_written: set[int] = set()
        if proto is not None:
            extra_nones = [None] * max(len(expr.args or []) - len(proto.args), 0)
            for ty, argexpr in zip(chain(proto.args, extra_nones), expr.args or []):
                if argexpr is def_size_arg:
                    assert def_size is not None
                    value = {(None, def_size)}
                else:
                    value = self._expr(argexpr)

                if not value:
                    continue
                if isinstance(ty, SimTypePointer) and ty.disposition == PointerDisposition.IN:
                    # the callee only reads the pointee, but may write through pointers stored in it
                    read_only_values.append(value)
                else:
                    arg_values.append(value)

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
                            out_written.update((stackref, stackref + extra))
                        else:
                            self.stackvar_get(stackref, extra, size)
        else:
            for argexpr in expr.args or []:
                arg_values.append(self._expr(argexpr))

        # kill caller-saved registers

        # determine the calling convention of the call
        expr_cc = self.variable_map.calling_convention(expr) if self.variable_map is not None else None
        if expr_cc is not None:
            cc = expr_cc
        elif target is not None and target.calling_convention is not None:
            cc = target.calling_convention
        else:
            cc = default_cc_for_project(self.project)
            assert cc is not None
            cc = cc(self.arch)

        # Conservative argument-register uses.
        # When we are not sure about the exact number of arguments that this call takes, assume every argument register
        # is potentially used by the call.
        if not isinstance(expr.target, str) and (
            (proto is None and expr.args is None)
            or (
                proto is not None
                and proto.variadic
                and not _has_explicit_variadic_args(proto)
                and (expr.args is None or len(expr.args) <= len(proto.args))
            )
        ):
            arg_values.extend(self._use_potential_arg_regs(cc))

        # kill caller-saved registers; the call becomes their definition
        call_loc = self._acodeloc()
        clobbered_by = frozenset((call_loc,))
        for reg_name in call_clobbered_regs(cc, target, self.arch):
            reg_offset, _ = self.arch.registers[reg_name]
            base_off, base_size = get_reg_offset_base_and_size(reg_offset, self.arch)
            self.state.live_registers.pop(base_off, None)
            for suboff in range(base_off, base_off + base_size):
                self.state.register_blackout[suboff] = clobbered_by
                self.state.register_defs.pop(suboff, None)
        for reg in cc.arch.vex_cc_regs or []:
            self.state.live_registers.pop(reg.vex_offset, None)
            for suboff in range(reg.vex_offset, reg.vex_offset + reg.size):
                self.state.register_blackout[suboff] = clobbered_by
                self.state.register_defs.pop(suboff, None)

        if self._model_escapes:
            passed = self._escaped_offsets(arg_values) | self._escaped_offsets(read_only_values, through_only=True)
            self._clobber_escaped_stackvars(call_loc, passed, out_written)

        return set()

    def _use_potential_arg_regs(self, cc: SimCC) -> list[Value]:
        """
        Record a conservative set of argument registers as used by the call when we are not sure about the exact
        function prototype.
        """
        values: list[Value] = []
        for reg_name in chain(cc.ARG_REGS or [], cc.FP_ARG_REGS or []):
            if reg_name not in self.arch.registers:
                continue
            reg_offset, reg_size = self.arch.registers[reg_name]
            base_off, _ = get_reg_offset_base_and_size(reg_offset, self.arch)
            if base_off in self.state.register_blackout:
                # the register was clobbered by a preceding call; no definition can reach here
                continue
            if not any(suboff in self.state.register_defs for suboff in range(reg_offset, reg_offset + reg_size)):
                # no definition of this register reaches this call site; do not synthesize an extern definition
                continue
            values.append(self.register_get(reg_offset, reg_size, None))
        return values

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
        return (
            self.state.live_vvars[expr.varid]
            if not has_conflicting_value_types(self.state.live_vvars[expr.varid])
            else set()
        )

    def _handle_expr_Register(self, expr: Register):
        return self.register_get(expr.reg_offset, expr.size, expr)

    def _handle_expr_IRegister(self, expr: IRegister):
        offset = expr.concrete_reg_offset()
        if offset is None:
            self._expr(expr.reg_offset)
            return set()
        return self.register_get(offset, expr.size, expr)

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
            self.state.pending_ptr_defines[expr.offset] = [(self._acodeloc(), expr)]
            # if this is the first time we've ever seen anything resembling this stackvar,
            # force this to be a def. otherwise, track future uses of this reference.
            # if we get to the end of the block and we haven't seen it used yet,
            # we'll require no more reads-before-writes in the rest of the function
            # to call this a new def
            if expr.offset not in self.state.stackvar_bases:
                self.stackvar_get(expr.offset, 0, 1)
                self.state.pending_ptr_defines[expr.offset] = [(self._acodeloc(), expr)]
        else:
            self.state.pending_ptr_defines[expr.offset].append((self._acodeloc(), expr))

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

    def _handle_expr_Array(self, expr) -> Value:
        for element in expr.elements:
            self._expr(element)
        return set()

    def _handle_expr_Struct(self, expr) -> Value:
        for field in expr.fields.values():
            self._expr(field)
        return set()

    def _handle_expr_String(self, expr) -> Value:  # pylint:disable=unused-argument, no-self-use
        return set()

    def _handle_expr_Let(self, expr) -> Value:
        return set()

    def _handle_expr_FunctionLikeMacro(self, expr) -> Value:
        for arg in expr.args:
            self._expr(arg)
        return set()

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

    # pylint: disable=unused-argument,no-self-use
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
    _handle_binop_HAddV = _unreachable
    _handle_binop_QAddV = _unreachable
    _handle_binop_QSubV = _unreachable
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
