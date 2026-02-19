from __future__ import annotations
from typing import TYPE_CHECKING, TypeAlias
from collections import defaultdict
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
        register_blackout: set[int] | None = None,
        live_vvars: MutableMapping[int, Value] | None = None,
        stackvar_bases: MutableMapping[int, tuple[int, int]] | None = None,
        register_bases: MutableMapping[int, tuple[int, int]] | None = None,
        stackvar_defs: MutableMapping[int, set[Def]] | None = None,
        register_defs: MutableMapping[int, set[Def]] | None = None,
        pending_ptr_defines_nonlocal_live: set[int] | None = None,
    ):
        self.arch = arch
        self.func = func

        self.register_blackout = set(register_blackout or ())
        self.live_registers = defaultdict(set, {} if live_registers is None else live_registers)
        self.live_stackvars = defaultdict(set, {} if live_stackvars is None else live_stackvars)
        self.live_vvars = defaultdict(set, {} if live_vvars is None else live_vvars)
        self.live_tmps: MutableMapping[int, Value] = defaultdict(
            set
        )  # tmps are internal to a block only and never propagated from another state

        self.stackvar_bases: MutableMapping[int, tuple[int, int]] = stackvar_bases if stackvar_bases is not None else {}
        self.register_bases: MutableMapping[int, tuple[int, int]] = register_bases if register_bases is not None else {}
        self.pending_ptr_defines: dict[int, list[tuple[AILCodeLocation, StackBaseOffset]]] = {}
        self.pending_ptr_defines_nonlocal_live = pending_ptr_defines_nonlocal_live or set()
        self.stackvar_defs = defaultdict(set, {} if stackvar_defs is None else stackvar_defs)
        self.register_defs = defaultdict(set, {} if register_defs is None else register_defs)

    def stackvar_unify(self, offset: int, size: int) -> tuple[int, int, set[int]]:
        seen = (offset, offset + size)
        queue = [(offset, offset + size)]
        popped: set[int] = set()
        while queue:
            offset, eoffset = queue.pop()
            for suboffset in range(offset, eoffset):
                noffset, nsize = self.stackvar_bases.get(suboffset, (suboffset, 0))
                neoffset = noffset + nsize
                if noffset < seen[0]:
                    queue.append((noffset, seen[0]))
                    seen = (noffset, seen[1])
                if neoffset > seen[1]:
                    queue.append((seen[1], neoffset))
                    seen = (seen[0], neoffset)
                if nsize != 0:
                    popped.add(noffset)

        final_offset, final_size = (seen[0], seen[1] - seen[0])
        for suboffset in range(*seen):
            self.stackvar_bases[suboffset] = (final_offset, final_size)

        return (final_offset, final_size, popped)

    def register_unify(self, offset: int, size: int) -> tuple[int, int, set[int]]:
        seen = (offset, offset + size)
        queue = [(offset, offset + size)]
        popped: set[int] = set()
        while queue:
            offset, eoffset = queue.pop()
            for suboffset in range(offset, eoffset):
                noffset, nsize = self.register_bases.get(suboffset, (suboffset, 0))
                neoffset = noffset + nsize
                if noffset < seen[0]:
                    queue.append((noffset, seen[0]))
                    seen = (noffset, seen[1])
                if neoffset > seen[1]:
                    queue.append((seen[1], neoffset))
                    seen = (seen[0], neoffset)
                if nsize != 0:
                    popped.add(noffset)

        final_offset, final_size = (seen[0], seen[1] - seen[0])
        for suboffset in range(*seen):
            self.register_bases[suboffset] = (final_offset, final_size)

        return (final_offset, final_size, popped)

    def copy(self) -> TraversalState:
        return TraversalState(
            self.arch,
            self.func,
            # these get copied
            live_registers=self.live_registers,
            live_stackvars=self.live_stackvars,
            register_blackout=self.register_blackout,
            live_vvars=self.live_vvars,
            pending_ptr_defines_nonlocal_live=set(self.pending_ptr_defines_nonlocal_live),
            stackvar_bases=dict(self.stackvar_bases),
            stackvar_defs={k: set(v) for k, v in self.stackvar_defs.items()},
            register_bases=dict(self.register_bases),
            register_defs={k: set(v) for k, v in self.register_defs.items()},
        )

    def merge(self, *others: TraversalState) -> bool:
        merge_occurred = False

        for o in others:
            for k, v in o.live_registers.items():
                merge_occurred |= bool(v.difference(self.live_registers[k]))
                self.live_registers[k].update(v)
            for k, v in o.live_stackvars.items():
                merge_occurred |= bool(v.difference(self.live_stackvars[k]))
                self.live_stackvars[k].update(v)
            for k, v in o.live_vvars.items():
                merge_occurred |= bool(v.difference(self.live_vvars[k]))
                self.live_vvars[k].update(v)
            for k0, (k1, s1) in o.stackvar_bases.items():
                k2, s2 = self.stackvar_bases.get(k0, (k0, 0))
                k3 = min(k1, k2)
                s3 = max(k1 + s1, k2 + s2) - k3
                if (k2, s2) != (k3, s3):
                    merge_occurred = True
                    self.stackvar_bases[k0] = (k3, s3)
            for k0, (k1, s1) in o.register_bases.items():
                k2, s2 = self.register_bases.get(k0, (k0, 0))
                k3 = min(k1, k2)
                s3 = max(k1 + s1, k2 + s2) - k3
                if (k2, s2) != (k3, s3):
                    merge_occurred = True
                    self.register_bases[k0] = (k3, s3)
            for k, d in o.stackvar_defs.items():
                merge_occurred |= bool(d.difference(self.stackvar_defs[k]))
                self.stackvar_defs[k].update(d)
            for k, d in o.register_defs.items():
                merge_occurred |= bool(d.difference(self.register_defs[k]))
                self.register_defs[k].update(d)
            merge_occurred |= bool(
                o.pending_ptr_defines_nonlocal_live.difference(self.pending_ptr_defines_nonlocal_live)
            )
            self.pending_ptr_defines_nonlocal_live.update(o.pending_ptr_defines_nonlocal_live)
            merge_occurred |= bool(o.register_blackout.difference(self.register_blackout))
            self.register_blackout.update(o.register_blackout)

        return merge_occurred
