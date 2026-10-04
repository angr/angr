from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, MutableMapping
from typing import TYPE_CHECKING

from angr.ailment.expression import StackBaseOffset
from angr.code_location import AILCodeLocation
from angr.utils.cow_interval_map import COWIntervalMap
from angr.utils.cowdict import DefaultChainMapCOW, merge_candidate_keys

if TYPE_CHECKING:
    from angr.analyses.decompiler.ssailification.ssailification import Def

# (stack offset | None, const value or offset from orig stack offset)
type Value = "set[tuple[int | None, int]]"


def has_conflicting_value_types(vs: Value) -> bool:
    """
    Value contains two types of entries: ``(int, *)`` that indicates a stack offset, and ``(None, int)`` that
    indicates a constant value. This method returns True if a set of Values contains both types of entries, otherwise
    False.

    """

    is_spoffset, is_const = False, False
    for v in vs:
        if v[0] is not None:
            is_spoffset = True
        else:
            is_const = True
        if is_spoffset and is_const:
            return True
    return False


class TraversalState:
    """
    The abstract state for the traversal engine.
    """

    def __init__(
        self,
        arch,
        func,
        live_registers: MutableMapping[int, Value] | None = None,
        live_stackvars: DefaultChainMapCOW[int, Value] | None = None,
        register_blackout: Mapping[int, frozenset[AILCodeLocation]] | None = None,
        live_vvars: DefaultChainMapCOW[int, Value] | None = None,
        stackvar_bases: COWIntervalMap[tuple[int, int]] | None = None,
        register_bases: MutableMapping[int, tuple[int, int]] | None = None,
        stackvar_defs: COWIntervalMap[set[Def]] | None = None,
        register_defs: MutableMapping[int, set[Def]] | None = None,
        pending_ptr_defines_nonlocal_live: set[int] | None = None,
    ):
        self.arch = arch
        self.func = func

        # register byte offset -> code locations of the calls that clobbered it. The values are immutable so that
        # copying a state (which happens for every block visit) is a shallow dict copy.
        self.register_blackout: dict[int, frozenset[AILCodeLocation]] = (
            dict(register_blackout) if register_blackout else {}
        )
        self.live_registers = defaultdict(set, {} if live_registers is None else live_registers)
        self.live_stackvars: DefaultChainMapCOW[int, Value] = (
            DefaultChainMapCOW(default_factory=set, collapse_threshold=50)
            if live_stackvars is None
            else live_stackvars.copy()
        )
        self.live_vvars = (
            DefaultChainMapCOW(default_factory=set, collapse_threshold=50) if live_vvars is None else live_vvars.copy()
        )
        self.live_tmps: MutableMapping[int, Value] = defaultdict(
            set
        )  # tmps are internal to a block only and never propagated from another state

        # stack byte offset -> (offset, size) of the variable covering it
        self.stackvar_bases: COWIntervalMap[tuple[int, int]] = (
            stackvar_bases.copy() if stackvar_bases is not None else COWIntervalMap(coalesce_equal=True)
        )
        self.register_bases: MutableMapping[int, tuple[int, int]] = register_bases if register_bases is not None else {}
        self.pending_ptr_defines: dict[int, list[tuple[AILCodeLocation, StackBaseOffset]]] = {}
        self.pending_ptr_defines_nonlocal_live = pending_ptr_defines_nonlocal_live or set()
        # stack byte offset -> reaching defs. bytes of one variable share a set object, which merge() updates in place
        self.stackvar_defs: COWIntervalMap[set[Def]] = (
            COWIntervalMap() if stackvar_defs is None else stackvar_defs.copy()
        )
        self.register_defs = defaultdict(set, {} if register_defs is None else register_defs)

    def stackvar_unify(self, offset: int, size: int) -> tuple[int, int, set[int]]:
        lo, hi = offset, offset + size
        queue = [(lo, hi)]
        popped: set[int] = set()
        bases = self.stackvar_bases
        while queue:
            qlo, qhi = queue.pop()
            for _, _, (noffset, nsize) in bases.overlapping(qlo, qhi):
                neoffset = noffset + nsize
                if noffset < lo:
                    queue.append((noffset, lo))
                    lo = noffset
                if neoffset > hi:
                    queue.append((hi, neoffset))
                    hi = neoffset
                if nsize != 0:
                    popped.add(noffset)

        bases.assign(lo, hi, (lo, hi - lo))
        return lo, hi - lo, popped

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
            stackvar_bases=self.stackvar_bases,
            stackvar_defs=self.stackvar_defs,
            register_bases=dict(self.register_bases),
            register_defs={k: set(v) for k, v in self.register_defs.items()},
        )

    def merge(self, *others: TraversalState) -> bool:
        merge_occurred = False

        for o in others:
            # live_registers (and other dict-like data structures) is a ChainMapCOW, which means each lookup is
            # N-times more expensive than a single dict lookup (where N is the chain map depth). Caching the
            # lookups is important.
            for k, v in o.live_registers.items():
                dst = self.live_registers[k]
                old_len = len(dst)
                dst.update(v)
                merge_occurred |= len(dst) > old_len

            # merge_candidate_keys() returns the keys after the shared suffix of two COW chain maps, so we avoid
            # iterating the shared histories of two COW chain maps.
            self.live_stackvars = self.live_stackvars.clean()
            for k in merge_candidate_keys(self.live_stackvars, o.live_stackvars):
                v = o.live_stackvars.get(k)
                if v is None:
                    continue
                dst = self.live_stackvars[k]
                old_len = len(dst)
                dst.update(v)
                merge_occurred |= len(dst) > old_len

            self.live_vvars = self.live_vvars.clean()
            for k in merge_candidate_keys(self.live_vvars, o.live_vvars):
                v = o.live_vvars.get(k)
                if v is None:
                    continue
                dst = self.live_vvars[k]
                old_len = len(dst)
                dst.update(v)
                merge_occurred |= len(dst) > old_len

            # every byte of a segment lies inside its (offset, size) value, so the hull with an unbound byte's
            # (byte, 0) default is the other value itself
            bases = self.stackvar_bases
            for lo, hi, (k1, s1) in list(bases.unshared_segments(o.stackvar_bases)):
                pieces = []
                cur = lo
                for slo, shi, (k2, s2) in bases.overlapping(lo, hi):
                    slo, shi = max(slo, lo), min(shi, hi)
                    if cur < slo:
                        pieces.append((cur, slo, (k1, s1)))
                    k3 = min(k1, k2)
                    s3 = max(k1 + s1, k2 + s2) - k3
                    if (k2, s2) != (k3, s3):
                        pieces.append((slo, shi, (k3, s3)))
                    cur = shi
                if cur < hi:
                    pieces.append((cur, hi, (k1, s1)))
                if pieces:
                    merge_occurred = True
                    for plo, phi, v in pieces:
                        bases.assign(plo, phi, v)

            for k0, (k1, s1) in o.register_bases.items():
                k2, s2 = self.register_bases.get(k0, (k0, 0))
                k3 = min(k1, k2)
                s3 = max(k1 + s1, k2 + s2) - k3
                if (k2, s2) != (k3, s3):
                    merge_occurred = True
                    self.register_bases[k0] = (k3, s3)

            # sets are updated in place, so the update reaches every byte (and every state) sharing the set
            sdefs = self.stackvar_defs
            for lo, hi, d in list(sdefs.unshared_segments(o.stackvar_defs)):
                gaps = []
                cur = lo
                for slo, shi, dst in sdefs.overlapping(lo, hi):
                    if cur < slo:
                        gaps.append((cur, slo))
                    old_len = len(dst)
                    dst.update(d)
                    merge_occurred |= len(dst) > old_len
                    cur = shi
                if cur < hi:
                    gaps.append((cur, hi))
                for glo, ghi in gaps:
                    sdefs.assign(glo, ghi, set(d))
                    merge_occurred |= bool(d)

            for k, d in o.register_defs.items():
                dst = self.register_defs[k]
                old_len = len(dst)
                dst.update(d)
                merge_occurred |= len(dst) > old_len

            old_len = len(self.pending_ptr_defines_nonlocal_live)
            self.pending_ptr_defines_nonlocal_live.update(o.pending_ptr_defines_nonlocal_live)
            merge_occurred |= len(self.pending_ptr_defines_nonlocal_live) > old_len

            for suboff, locs in o.register_blackout.items():
                dst_locs = self.register_blackout.get(suboff)
                if dst_locs is None:
                    self.register_blackout[suboff] = locs
                    merge_occurred = True
                elif not locs <= dst_locs:
                    self.register_blackout[suboff] = dst_locs | locs
                    merge_occurred = True

        return merge_occurred
