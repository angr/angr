from __future__ import annotations
from collections import defaultdict
from typing import TYPE_CHECKING, TypeAlias
from collections.abc import MutableMapping

from angr.ailment.expression import StackBaseOffset
from angr.code_location import AILCodeLocation

if TYPE_CHECKING:
    from angr.analyses.decompiler.ssailification.ssailification import Def

# (stack offset | None, const value or offset from orig stack offset)
Value: TypeAlias = "set[tuple[int | None, int]]"


class TraversalState:
    """
    The abstract state for the traversal engine.
    """

    def __init__(
        self,
        arch,
        func,
        live_registers: MutableMapping[int, Value] | None = None,
        live_stackvars: MutableMapping[int, Value] | None = None,
        live_vvars: MutableMapping[int, Value] | None = None,
        stackvar_bases: MutableMapping[int, tuple[int, int]] | None = None,
        stackvar_defs: MutableMapping[int, set[Def]] | None = None,
        pending_ptr_defines_nonlocal_live: set[int] | None = None,
    ):
        self.arch = arch
        self.func = func

        self.live_registers = defaultdict(set, {} if live_registers is None else live_registers)
        self.live_stackvars = defaultdict(set, {} if live_stackvars is None else live_stackvars)
        self.live_vvars = defaultdict(set, {} if live_vvars is None else live_vvars)
        self.live_tmps: MutableMapping[int, Value] = defaultdict(
            set
        )  # tmps are internal to a block only and never propagated from another state

        self.stackvar_bases: MutableMapping[int, tuple[int, int]] = stackvar_bases if stackvar_bases is not None else {}
        self.pending_ptr_defines: dict[int, tuple[AILCodeLocation, StackBaseOffset]] = {}
        self.pending_ptr_defines_nonlocal_live = pending_ptr_defines_nonlocal_live or set()
        self.stackvar_defs = defaultdict(set, set() if stackvar_defs is None else stackvar_defs)

    def stackvar_unify(self, offset: int, size: int) -> tuple[int, int, set[int]]:
        if (uhoh := self.stackvar_bases.get(offset, None)) == (offset, size):
            return (offset, size, set())
        if uhoh is None:
            full_offset, full_size = offset, size
        else:
            cur_offset, cur_size = uhoh
            if cur_offset <= offset and cur_offset + cur_size >= offset + size:
                return (cur_offset, cur_size, set())
            full_offset = min(cur_offset, offset)
            full_size = max(cur_offset + cur_size, offset + size) - full_offset

        final_cell = full_offset + full_size - 1
        uhoh = self.stackvar_bases.get(final_cell, None)
        if uhoh is not None:
            full_size = max(full_size, uhoh[0] + uhoh[1] - full_offset)

        popped = self.stackvar_poprange(full_offset, full_size)
        for suboff in range(offset, offset + size):
            self.stackvar_bases[suboff] = (full_offset, full_size)
        return (full_offset, full_size, popped)

    def stackvar_poprange(self, offset: int, size: int) -> set[int]:
        popped = set()
        for suboff in range(offset, offset + size):
            if (a := self.stackvar_bases.pop(suboff, None)) is not None:
                popped.add(a[0])
        return popped

    def copy(self) -> TraversalState:
        return TraversalState(
            self.arch,
            self.func,
            # these get copied
            live_registers=self.live_registers,
            live_stackvars=self.live_stackvars,
            live_vvars=self.live_vvars,
            pending_ptr_defines_nonlocal_live=self.pending_ptr_defines_nonlocal_live,
            stackvar_bases=dict(self.stackvar_bases),
            stackvar_defs=dict(self.stackvar_defs),
        )

    def merge(self, *others: TraversalState) -> bool:
        merge_occurred = False

        # all_regs = defaultdict(set, {k: v.copy() for k, v in self.live_registers.items()})
        # all_stackvars = defaultdict(set, {k: v.copy() for k, v in self.live_stackvars.items()})
        # all_vvars = defaultdict(set, {k: v.copy() for k, v in self.live_vvars.items()})
        all_regs = self.live_registers
        all_stackvars = self.live_stackvars
        all_vvars = self.live_vvars
        ppdnl = self.pending_ptr_defines_nonlocal_live

        for o in others:
            for k, v in o.live_registers.items():
                merge_occurred |= bool(v.difference(all_regs[k]))
                all_regs[k].update(v)
            for k, v in o.live_stackvars.items():
                merge_occurred |= bool(v.difference(all_stackvars[k]))
                all_stackvars[k].update(v)
            for k, v in o.live_vvars.items():
                merge_occurred |= bool(v.difference(all_vvars[k]))
                all_vvars[k].update(v)
            for k, s in set(o.stackvar_bases.values()):
                merge_occurred |= (k, s) != self.stackvar_unify(k, s)
            merge_occurred |= bool(o.pending_ptr_defines_nonlocal_live.difference(ppdnl))
            ppdnl.update(o.pending_ptr_defines_nonlocal_live)

        # self.live_registers = all_regs
        # self.live_stackvars = all_stackvars
        # self.live_vvars = all_vvars
        return merge_occurred
