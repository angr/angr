"""Fuzzy common-substring discovery over a token stream.

The algorithm is sparse local self-alignment, the BLAST/MUMmer family:

1. **Seed** -- index every k-gram of the token stream. Buckets whose
   multiplicity exceeds ``max_seed_multiplicity`` are masked out; without this
   low-complexity filter, ubiquitous tokens generate a quadratic number of seed
   pairs. Optional winnowing (Schleimer et al., SIGMOD'03) keeps only the
   minimum hash in each window of ``window`` consecutive k-grams, which thins
   the seed set while still guaranteeing that any exact match of length
   >= ``k + window - 1`` produces a seed.
2. **Chain** -- every seed pair ``(i, j)`` votes for diagonal ``d = j - i``.
   Per diagonal the seed positions are cut into runs separated by more than
   ``max_gap``, and runs on nearby diagonals are fused only when they really
   overlap (see :func:`_merge_diagonals`).
3. **Align** -- each candidate is refined by a banded Smith-Waterman with
   affine gaps over the substitution model, yielding exact boundaries and an
   identity ratio. The band absorbs indels, so a repeat whose seeds landed on
   two diagonals is still recovered as a single match.
4. **Cluster** -- surviving alignments are merged into groups of >= 2
   occurrences by union-find over overlapping intervals, then de-overlapped by
   a weight-maximizing interval-scheduling pass.

Everything here is pure: it operates on lists of integer token ids and knows
nothing about angr. :mod:`.finder` supplies the ids.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_l = logging.getLogger(__name__)

_M, _X, _Y = 0, 1, 2
_NEG = float("-inf")


@dataclass(frozen=True, order=True)
class Interval:
    """A half-open token range ``[start, end)``."""

    start: int
    end: int

    def __len__(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Interval) -> bool:
        return self.start < other.end and other.start < self.end

    def overlap_len(self, other: Interval) -> int:
        return max(0, min(self.end, other.end) - max(self.start, other.start))


@dataclass
class Alignment:
    """One fuzzy match between two token ranges."""

    a: Interval
    b: Interval
    score: float
    matched: int
    columns: int

    @property
    def identity(self) -> float:
        return self.matched / self.columns if self.columns else 0.0


@dataclass
class PatternCluster:
    """A group of occurrences of one fuzzy pattern."""

    occurrences: list[Interval]
    score: float
    identity: float
    alignments: list[Alignment] = field(default_factory=list)

    @property
    def size(self) -> int:
        return max((len(o) for o in self.occurrences), default=0)

    @property
    def savings(self) -> float:
        """Tokens removed by outlining: every occurrence but one disappears."""
        if len(self.occurrences) < 2:
            return 0.0
        mean = sum(len(o) for o in self.occurrences) / len(self.occurrences)
        return (len(self.occurrences) - 1) * mean * self.identity

    def spans(self) -> list[Interval]:
        return self.occurrences


@dataclass
class AlignParams:
    """Knobs for the whole pipeline."""

    k: int = 4
    window: int = 0
    max_seed_multiplicity: int = 80
    min_anchors: int = 4
    max_gap: int = 30
    band: int = 16
    pad: int = 40
    match: float = 3.0
    klass_match: float = 1.0
    mismatch: float = -2.0
    gap_open: float = -4.0
    gap_extend: float = -1.0
    min_score: float = 40.0
    min_identity: float = 0.5
    min_size: int = 8
    min_occurrences: int = 2
    max_candidates: int = 4000
    overlap_ratio: float = 0.5
    allow_tandem: bool = False
    #: template search: a diagonal needs this many statements of the template voting for
    #: it to be aligned, or a quarter of the template's concrete statements if that is
    #: fewer, so small templates are never pruned
    min_votes: int = 5


class ScoreModel:
    """Substitution score between two shape ids."""

    def __init__(self, klass_of_shape: list[int], params: AlignParams, glue: frozenset[int] = frozenset()):
        self.klass_of_shape = klass_of_shape
        self.match = params.match
        self.klass_match = params.klass_match
        self.mismatch = params.mismatch
        #: shape ids of unconditional jumps: control glue between blocks, which neither
        #: makes two stretches of code alike nor keeps them apart
        self.glue = glue

    def __call__(self, a: int, b: int) -> float:
        if a == b:
            return 0.0 if a in self.glue else self.match
        if self.klass_of_shape[a] == self.klass_of_shape[b]:
            return self.klass_match
        return self.mismatch


def find_seeds(
    ids: list[int],
    params: AlignParams,
    segment: list[int] | None = None,
    glue: frozenset[int] = frozenset(),
) -> dict[tuple[int, ...], list[int]]:
    """k-gram index, low-complexity-masked and optionally winnowed. With ``segment``, a
    k-gram that crosses from one segment into another is not a seed; nor is one made of
    unconditional jumps alone."""
    k = params.k
    n = len(ids)
    if n < k:
        return {}

    positions = range(n - k + 1)
    if params.window > 1:
        hashes = [hash(tuple(ids[i : i + k])) for i in positions]
        selected: set[int] = set()
        w = params.window
        for start in range(len(hashes) - w + 1):
            best_i = start
            best_h = hashes[start]
            for i in range(start + 1, start + w):
                if hashes[i] <= best_h:
                    best_h = hashes[i]
                    best_i = i
            selected.add(best_i)
        positions = sorted(selected)

    buckets: dict[tuple[int, ...], list[int]] = defaultdict(list)
    for i in positions:
        if segment is not None and segment[i] != segment[i + k - 1]:
            continue
        gram = tuple(ids[i : i + k])
        if glue and all(g in glue for g in gram):
            continue
        buckets[gram].append(i)

    return {gram: pos for gram, pos in buckets.items() if 2 <= len(pos) <= params.max_seed_multiplicity}


def chain_seeds(
    buckets: dict[tuple[int, ...], list[int]], params: AlignParams, segment: list[int] | None = None
) -> list[tuple[int, int, int, int]]:
    """Group seed pairs by diagonal and cut them into colinear runs. With ``segment``, a
    run also ends where either copy would cross into another segment.

    Returns ``(diagonal, start, end, anchors)`` candidates, where ``[start, end)``
    is the range in the *first* (lower-index) copy.
    """
    diag: dict[int, list[int]] = defaultdict(list)
    for pos in buckets.values():
        for a in range(len(pos)):
            for b in range(a + 1, len(pos)):
                diag[pos[b] - pos[a]].append(pos[a])

    raw: list[tuple[int, int, int, int]] = []
    min_d = params.k if not params.allow_tandem else 1
    for d, xs in diag.items():
        if d < min_d or len(xs) < params.min_anchors:
            continue
        xs.sort()
        run = [xs[0]]
        for x in xs[1:]:
            same_segments = segment is None or (segment[x] == segment[run[0]] and segment[x + d] == segment[run[0] + d])
            if x - run[-1] <= params.max_gap and same_segments:
                run.append(x)
                continue
            if len(run) >= params.min_anchors:
                raw.append((d, run[0], run[-1] + params.k, len(run)))
            run = [x]
        if len(run) >= params.min_anchors:
            raw.append((d, run[0], run[-1] + params.k, len(run)))

    return _merge_diagonals(raw, params)


def _merge_diagonals(raw: list[tuple[int, int, int, int]], params: AlignParams) -> list[tuple[int, int, int, int]]:
    """Fold candidates on nearby diagonals whose ranges *overlap* into one candidate.

    Requiring a real overlap matters: two runs that merely sit near each other
    along ``i`` are usually two different repeat pairs (copy A vs copy B, and
    copy B vs copy C), and fusing them produces a candidate that describes
    neither. Runs separated by an indel are left split here on purpose -- the
    banded alignment in :func:`refine_candidates` spans the indel anyway, and
    the redundancy check there drops whichever copy loses.
    """
    if not raw:
        return []
    raw.sort(key=lambda c: (c[0], c[1]))
    merged: list[list[int]] = []
    for d, s, e, anchors in raw:
        for m in merged:
            if abs(m[0] - d) <= params.band and s < m[2] and m[1] < e:
                m[1] = min(m[1], s)
                m[2] = max(m[2], e)
                m[3] += anchors
                break
        else:
            merged.append([d, s, e, anchors])
    merged.sort(key=lambda m: (-(m[2] - m[1]), -m[3]))
    return [tuple(m) for m in merged[: params.max_candidates]]


def banded_sw(
    ids: list[int],
    a0: int,
    a1: int,
    b0: int,
    b1: int,
    band: int,
    score: ScoreModel,
    params: AlignParams,
    checkpoint: Callable[[], None] | None = None,
) -> Alignment | None:
    """Banded local alignment with affine gaps, restricted to ``|i - j| <= band``.

    Two unconditional jumps (``score.glue``) lined up score nothing, and such a column
    counts toward neither the matched columns nor the columns. Skipping one costs the
    usual gap: a free skip would let an alignment run on from one copy into the next,
    since reverse post-order often places copies side by side.
    """
    glue = score.glue
    la, lb = a1 - a0, b1 - b0
    if la <= 0 or lb <= 0:
        return None

    prev = [{}, {}, {}]
    ptr: dict[tuple[int, int, int], int] = {}
    best_score, best_cell = 0.0, None

    for i in range(1, la + 1):
        if checkpoint is not None:
            checkpoint()
        cur = [{}, {}, {}]
        lo = max(1, i - band)
        hi = min(lb, i + band)
        ai = ids[a0 + i - 1]
        for j in range(lo, hi + 1):
            s = score(ai, ids[b0 + j - 1])

            dm = prev[_M].get(j - 1, _NEG)
            dx = prev[_X].get(j - 1, _NEG)
            dy = prev[_Y].get(j - 1, _NEG)
            best_prev, best_state = 0.0, -1
            if dm > best_prev:
                best_prev, best_state = dm, _M
            if dx > best_prev:
                best_prev, best_state = dx, _X
            if dy > best_prev:
                best_prev, best_state = dy, _Y
            m = best_prev + s
            if m > 0:
                cur[_M][j] = m
                ptr[i, j, _M] = best_state
                if m > best_score:
                    best_score, best_cell = m, (i, j)

            om = prev[_M].get(j, _NEG) + params.gap_open
            ox = prev[_X].get(j, _NEG) + params.gap_extend
            x = max(om, ox)
            if x > 0:
                cur[_X][j] = x
                ptr[i, j, _X] = _M if om >= ox else _X

            om = cur[_M].get(j - 1, _NEG) + params.gap_open
            oy = cur[_Y].get(j - 1, _NEG) + params.gap_extend
            y = max(om, oy)
            if y > 0:
                cur[_Y][j] = y
                ptr[i, j, _Y] = _M if om >= oy else _Y

        prev = cur

    if best_cell is None:
        return None

    i, j = best_cell
    state = _M
    matched = columns = 0
    end_i, end_j = i, j
    while True:
        prev_state = ptr.get((i, j, state), -1)
        if state == _M:
            ai, bj = ids[a0 + i - 1], ids[b0 + j - 1]
            if not (ai in glue and bj in glue):
                columns += 1
                if ai == bj:
                    matched += 1
            i -= 1
            j -= 1
        elif state == _X:
            if ids[a0 + i - 1] not in glue:
                columns += 1
            i -= 1
        else:
            if ids[b0 + j - 1] not in glue:
                columns += 1
            j -= 1
        if prev_state == -1 or i <= 0 or j <= 0:
            break
        state = prev_state

    return Alignment(
        a=Interval(a0 + i, a0 + end_i),
        b=Interval(b0 + j, b0 + end_j),
        score=best_score,
        matched=matched,
        columns=columns,
    )


def refine_candidates(
    ids: list[int],
    candidates: list[tuple[int, int, int, int]],
    score: ScoreModel,
    params: AlignParams,
    checkpoint: Callable[[], None] | None = None,
    segment: list[int] | None = None,
) -> list[Alignment]:
    """Run banded Smith-Waterman on every chained candidate and keep the good ones. With
    ``segment``, each copy's window is clipped to the segment its seed lies in."""
    n = len(ids)
    bounds: dict[int, tuple[int, int]] = {}
    if segment is not None:
        for t, seg in enumerate(segment):
            lo_hi = bounds.get(seg)
            bounds[seg] = (t, t + 1) if lo_hi is None else (lo_hi[0], t + 1)
    out: list[Alignment] = []
    for d, s, e, _anchors in candidates:
        if checkpoint is not None:
            checkpoint()
        # candidates arrive longest-first, so an already-accepted alignment that
        # covers both sides of this one makes it redundant
        if any(a.a.start <= s and e <= a.a.end and a.b.start <= s + d and e + d <= a.b.end for a in out):
            continue
        a0, a1 = max(0, s - params.pad), min(n, e + params.pad)
        b0, b1 = max(0, s + d - params.pad), min(n, e + d + params.pad)
        # Padding must not let the two windows meet: if it does, the best local
        # alignment is the trivial one of the sequence with itself. Trim inside
        # the gap between the two cores only, so neither core is ever clipped.
        gap_lo, gap_hi = e, s + d
        if gap_hi >= gap_lo:
            a1 = min(a1, gap_hi)
            b0 = max(b0, gap_lo)
            if a1 > b0:
                mid = (gap_lo + gap_hi) // 2
                a1, b0 = mid, mid
        if segment is not None and s < n and s + d < n:
            sa, sb = bounds[segment[s]], bounds[segment[s + d]]
            a0, a1 = max(a0, sa[0]), min(a1, sa[1])
            b0, b1 = max(b0, sb[0]), min(b1, sb[1])
        if b0 >= n or a0 >= a1 or b0 >= b1:
            continue
        aln = banded_sw(ids, a0, a1, b0, b1, params.band + params.pad, score, params, checkpoint)
        if aln is None:
            continue
        if aln.score < params.min_score or aln.identity < params.min_identity:
            continue
        if len(aln.a) < params.min_size or len(aln.b) < params.min_size:
            continue
        if not params.allow_tandem and aln.a.overlaps(aln.b):
            continue
        out.append(aln)
    return out


def cluster_alignments(alignments: list[Alignment], params: AlignParams) -> list[PatternCluster]:
    """Merge pairwise alignments into groups of >= ``min_occurrences`` occurrences."""
    if not alignments:
        return []

    canon: list[Interval] = []

    def canonical(iv: Interval) -> int:
        for idx, c in enumerate(canon):
            ov = iv.overlap_len(c)
            if ov and ov / max(len(iv), len(c)) >= params.overlap_ratio:
                if len(iv) > len(c):
                    canon[idx] = iv
                return idx
        canon.append(iv)
        return len(canon) - 1

    edges: list[tuple[int, int, Alignment]] = []
    for aln in sorted(alignments, key=lambda x: -x.score):
        edges.append((canonical(aln.a), canonical(aln.b), aln))

    parent = list(range(len(canon)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for u, v, _ in edges:
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[ru] = rv

    groups: dict[int, set[int]] = defaultdict(set)
    group_edges: dict[int, list[Alignment]] = defaultdict(list)
    for u, v, aln in edges:
        root = find(u)
        groups[root].update((u, v))
        group_edges[root].append(aln)

    clusters: list[PatternCluster] = []
    for root, members in groups.items():
        occurrences = _deoverlap([canon[i] for i in members])
        if len(occurrences) < params.min_occurrences:
            continue
        alns = group_edges[root]
        clusters.append(
            PatternCluster(
                occurrences=sorted(occurrences),
                score=sum(a.score for a in alns) / len(alns),
                identity=sum(a.identity for a in alns) / len(alns),
                alignments=alns,
            )
        )

    clusters.sort(key=lambda c: (-c.savings, -c.score))
    return clusters


def select_disjoint(clusters: list[PatternCluster], overlap_ratio: float = 0.25) -> list[PatternCluster]:
    """Greedily pick the highest-savings clusters whose occurrences do not collide.

    Repeat finding legitimately reports the same code at several granularities
    (the whole inlined region, and the hot loop inside it). Outlining needs one
    decision per token, so callers that want to rewrite the graph take this
    subset while keeping the full list for reporting.
    """
    chosen: list[PatternCluster] = []
    claimed: list[Interval] = []
    for cluster in sorted(clusters, key=lambda c: (-c.savings, -c.score)):
        collides = False
        for occ in cluster.occurrences:
            for c in claimed:
                if occ.overlap_len(c) / max(1, len(occ)) > overlap_ratio:
                    collides = True
                    break
            if collides:
                break
        if collides:
            continue
        chosen.append(cluster)
        claimed.extend(cluster.occurrences)
    return chosen


def _deoverlap(intervals: list[Interval]) -> list[Interval]:
    """Weight-maximizing selection of mutually disjoint intervals (longest first)."""
    chosen: list[Interval] = []
    for iv in sorted(intervals, key=lambda x: (-len(x), x.start)):
        if not any(iv.overlaps(c) for c in chosen):
            chosen.append(iv)
    return chosen


def discover(
    ids: list[int],
    klass_of_shape: list[int],
    params: AlignParams | None = None,
    checkpoint: Callable[[], None] | None = None,
    segment: list[int] | None = None,
    glue: frozenset[int] = frozenset(),
) -> list[PatternCluster]:
    """Full pipeline: seed -> chain -> align -> cluster. ``checkpoint`` is called from the
    alignment loops, where the time goes; see :class:`.priority.Checkpoint`. ``segment``
    gives each token a segment number that no occurrence may cross out of, and ``glue`` the
    shape ids of unconditional jumps, which score nothing and cost nothing to skip."""
    params = params or AlignParams()
    score = ScoreModel(klass_of_shape, params, glue)
    buckets = find_seeds(ids, params, segment, glue)
    candidates = chain_seeds(buckets, params, segment)
    _l.debug("fuzzy patterns: %d seed buckets, %d chained candidates", len(buckets), len(candidates))
    alignments = refine_candidates(ids, candidates, score, params, checkpoint, segment)
    _l.debug("fuzzy patterns: %d alignments survived refinement", len(alignments))
    return cluster_alignments(alignments, params)
