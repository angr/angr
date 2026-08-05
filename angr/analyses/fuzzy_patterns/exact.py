"""Tier 2: maximal *exactly* shared sub-ranges inside a fuzzy family.

Tier 1 (:mod:`.align`) discovers that a set of regions are near-duplicates. That
is enough to understand a binary, but not enough to merge them: two regions that
align at 90% still differ somewhere, and collapsing them into one function would
be wrong.

This module finds the sub-ranges on which the occurrences agree *exactly* on
canonical shapes. Because :mod:`.tokenizer` already abstracts constants out of a
shape, "exactly equal shapes" means "identical modulo constants" -- the classic
Type-2 clone. Those ranges can be outlined into a single shared function with the
differing constants lifted into extra parameters, without changing semantics.

Cores are extracted greedily longest-first; each accepted core masks the token
ranges it consumed, and the search continues on the surviving fragments.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .align import Interval

_l = logging.getLogger(__name__)


@dataclass
class ExactCore:
    """A range on which several occurrences agree exactly on canonical shapes."""

    occurrences: list[Interval]
    length: int

    @property
    def support(self) -> int:
        return len(self.occurrences)

    @property
    def savings(self) -> int:
        return (self.support - 1) * self.length


@dataclass
class _Fragment:
    occ_index: int
    start: int
    tokens: tuple[int, ...]


def _best_common(fragments: list[_Fragment], length: int, min_support: int) -> list[tuple[int, int]] | None:
    """Positions of some substring of ``length`` shared by >= ``min_support`` occurrences.

    Returns ``[(fragment_index, offset), ...]``, at most one per occurrence.
    """
    seen: dict[tuple[int, ...], dict[int, tuple[int, int]]] = {}
    for fi, frag in enumerate(fragments):
        if len(frag.tokens) < length:
            continue
        local: set[tuple[int, ...]] = set()
        for off in range(len(frag.tokens) - length + 1):
            key = frag.tokens[off : off + length]
            if key in local:
                continue
            local.add(key)
            seen.setdefault(key, {}).setdefault(frag.occ_index, (fi, off))

    best: list[tuple[int, int]] | None = None
    for hits in seen.values():
        if len(hits) >= min_support and (best is None or len(hits) > len(best)):
            best = list(hits.values())
    return best


def find_exact_cores(
    ids: list[int],
    occurrences: list[Interval],
    *,
    min_len: int = 4,
    min_support: int = 2,
    max_cores: int = 32,
) -> list[ExactCore]:
    """Greedily extract maximal exactly-shared cores from a fuzzy family."""
    if len(occurrences) < min_support:
        return []

    fragments = [
        _Fragment(occ_index=i, start=occ.start, tokens=tuple(ids[occ.start : occ.end]))
        for i, occ in enumerate(occurrences)
    ]

    cores: list[ExactCore] = []
    while len(cores) < max_cores:
        upper = sorted((len(f.tokens) for f in fragments), reverse=True)
        if len(upper) < min_support or upper[min_support - 1] < min_len:
            break

        # longest length with sufficient support is monotone: binary search it
        lo, hi, found = min_len, upper[min_support - 1], None
        while lo <= hi:
            mid = (lo + hi) // 2
            hits = _best_common(fragments, mid, min_support)
            if hits is None:
                hi = mid - 1
            else:
                found = (mid, hits)
                lo = mid + 1

        if found is None:
            break
        length, hits = found
        cores.append(
            ExactCore(
                occurrences=sorted(
                    Interval(fragments[fi].start + off, fragments[fi].start + off + length) for fi, off in hits
                ),
                length=length,
            )
        )

        consumed = {fi: off for fi, off in hits}
        new_fragments: list[_Fragment] = []
        for fi, frag in enumerate(fragments):
            off = consumed.get(fi)
            if off is None:
                new_fragments.append(frag)
                continue
            if off >= min_len:
                new_fragments.append(_Fragment(frag.occ_index, frag.start, frag.tokens[:off]))
            tail = off + length
            if len(frag.tokens) - tail >= min_len:
                new_fragments.append(_Fragment(frag.occ_index, frag.start + tail, frag.tokens[tail:]))
        fragments = new_fragments

    cores.sort(key=lambda c: -c.savings)
    return cores
