# pylint:disable=protected-access
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterator

# a chunk is (starts, ends, values); chunks are never mutated once built, so maps can share them
type _Chunk[V] = tuple[list[int], list[int], list[V]]
type Segment[V] = tuple[int, int, V]


def _identical(a, b) -> bool:
    return a is b


def _equal(a, b) -> bool:
    return a is b or a == b


class IntervalMapCOW[V]:
    """
    A piecewise-constant map from integers to values, stored as sorted, non-overlapping segments ``[start, end) ->
    value``.
    """

    CHUNK_SIZE: int = 64

    __slots__ = ("_chunks", "_coalesce", "_firsts", "_shared")

    def __init__(self, coalesce_equal: bool = False):
        """
        :param coalesce_equal:  Merge adjacent segments whose values are equal (==). Otherwise only adjacent segments
                                bound to the very same object are merged. Use it only for immutable values.
        """
        self._chunks: list[_Chunk[V]] = []
        self._firsts: list[int] = []  # start of the first segment of each chunk
        self._shared = False
        self._coalesce: Callable[[object, object], bool] = _equal if coalesce_equal else _identical

    def copy(self) -> IntervalMapCOW[V]:
        o = IntervalMapCOW.__new__(IntervalMapCOW)
        o._chunks = self._chunks
        o._firsts = self._firsts
        o._coalesce = self._coalesce
        o._shared = self._shared = True
        return o

    def _own(self) -> None:
        if self._shared:
            self._chunks = list(self._chunks)
            self._firsts = list(self._firsts)
            self._shared = False

    #
    # Reads
    #

    def get[TD](self, key: int, default: TD = None) -> V | TD:
        ci = bisect_right(self._firsts, key) - 1
        if ci < 0:
            return default
        starts, ends, values = self._chunks[ci]
        i = bisect_right(starts, key) - 1
        if key < ends[i]:
            return values[i]
        return default

    def __contains__(self, key: int) -> bool:
        ci = bisect_right(self._firsts, key) - 1
        if ci < 0:
            return False
        starts, ends, _ = self._chunks[ci]
        return key < ends[bisect_right(starts, key) - 1]

    def __getitem__(self, key: int) -> V:
        ci = bisect_right(self._firsts, key) - 1
        if ci >= 0:
            starts, ends, values = self._chunks[ci]
            i = bisect_right(starts, key) - 1
            if key < ends[i]:
                return values[i]
        raise KeyError(key)

    def __bool__(self) -> bool:
        return bool(self._chunks)

    def __len__(self) -> int:
        """
        The number of bound keys.
        """
        return sum(e - s for s, e, _ in self.segments())

    def next_key(self, key: int) -> int | None:
        """
        Return the smallest bound key that is >= `key`, or None.
        """
        firsts = self._firsts
        ci = max(bisect_right(firsts, key) - 1, 0)
        while ci < len(firsts):
            starts, ends, _ = self._chunks[ci]
            i = bisect_right(ends, key)
            if i < len(starts):
                return max(starts[i], key)
            ci += 1
        return None

    def segment_count(self) -> int:
        return sum(len(c[0]) for c in self._chunks)

    def segments(self) -> Iterator[Segment[V]]:
        for starts, ends, values in self._chunks:
            yield from zip(starts, ends, values)

    def overlapping(self, lo: int, hi: int) -> Iterator[Segment[V]]:
        """
        Yield (unclipped) segments that overlap [lo, hi), in ascending order.
        """
        if lo >= hi:
            return
        firsts = self._firsts
        ci = max(bisect_right(firsts, lo) - 1, 0)
        n = len(firsts)
        while ci < n and firsts[ci] < hi:
            starts, ends, values = self._chunks[ci]
            i = bisect_right(ends, lo)
            m = len(starts)
            while i < m and starts[i] < hi:
                yield starts[i], ends[i], values[i]
                i += 1
            ci += 1

    def unshared_segments(self, other: IntervalMapCOW[V]) -> Iterator[Segment[V]]:
        """
        Yield segments of `other` that live in chunks this map does not share. Every other segment of `other` is bound
        identically in this map.
        """
        if other._chunks is self._chunks:
            return
        mine = {id(c) for c in self._chunks}
        for c in other._chunks:
            if id(c) not in mine:
                yield from zip(*c)

    #
    # Writes
    #

    def _splice(self, lo: int, hi: int, new: list[Segment[V]]) -> list[Segment[V]]:
        """
        Replace all bindings in [lo, hi) with `new` (sorted, disjoint, inside [lo, hi)), and return the removed
        bindings clipped to [lo, hi).
        """
        self._own()
        chunks, firsts = self._chunks, self._firsts
        if not chunks:
            if new:
                self._rechunk(0, 0, [s for s, _, _ in new], [e for _, e, _ in new], [v for _, _, v in new])
            return []

        ci0 = max(bisect_right(firsts, lo) - 1, 0)
        ci1 = max(bisect_left(firsts, hi) - 1, ci0)
        starts: list[int] = []
        ends: list[int] = []
        values: list[V] = []
        for c in chunks[ci0 : ci1 + 1]:
            starts += c[0]
            ends += c[1]
            values += c[2]

        i = bisect_right(ends, lo)
        j = bisect_left(starts, hi, lo=i)
        removed: list[Segment[V]] = []
        if i == j and not new:
            return removed

        mid_s: list[int] = []
        mid_e: list[int] = []
        mid_v: list[V] = []
        if i < j:
            if starts[i] < lo:
                mid_s.append(starts[i])
                mid_e.append(lo)
                mid_v.append(values[i])
            for k in range(i, j):
                removed.append((max(starts[k], lo), min(ends[k], hi), values[k]))
        for s, e, v in new:
            mid_s.append(s)
            mid_e.append(e)
            mid_v.append(v)
        if i < j and ends[j - 1] > hi:
            mid_s.append(hi)
            mid_e.append(ends[j - 1])
            mid_v.append(values[j - 1])

        # coalesce around the spliced region
        out_s, out_e, out_v = starts[:i], ends[:i], values[:i]
        coalesce = self._coalesce
        for s, e, v in zip(mid_s, mid_e, mid_v):
            if out_s and out_e[-1] == s and coalesce(out_v[-1], v):
                out_e[-1] = e
            else:
                out_s.append(s)
                out_e.append(e)
                out_v.append(v)
        if j < len(starts) and out_s and out_e[-1] == starts[j] and coalesce(out_v[-1], values[j]):
            out_e[-1] = ends[j]
            j += 1
        out_s += starts[j:]
        out_e += ends[j:]
        out_v += values[j:]

        # absorb a neighbor if the rebuilt region became small, to avoid fragmenting into tiny chunks
        if len(out_s) < self.CHUNK_SIZE // 4 and ci1 + 1 < len(chunks):
            ci1 += 1
            nxt = chunks[ci1]
            out_s += nxt[0]
            out_e += nxt[1]
            out_v += nxt[2]
        self._rechunk(ci0, ci1 + 1, out_s, out_e, out_v)
        return removed

    def _rechunk(self, ci0: int, ci1: int, starts: list[int], ends: list[int], values: list[V]) -> None:
        n = len(starts)
        size = self.CHUNK_SIZE
        if n <= size:
            new_chunks = [(starts, ends, values)] if n else []
        else:
            pieces = -(-n // (size // 2))
            step = -(-n // pieces)
            new_chunks = [(starts[k : k + step], ends[k : k + step], values[k : k + step]) for k in range(0, n, step)]
        self._chunks[ci0:ci1] = new_chunks
        self._firsts[ci0:ci1] = [c[0][0] for c in new_chunks]

    def assign(self, lo: int, hi: int, value: V) -> None:
        """
        Bind every key in [lo, hi) to `value`.
        """
        if lo < hi:
            self._splice(lo, hi, [(lo, hi, value)])

    def pop_range(self, lo: int, hi: int) -> list[Segment[V]]:
        """
        Unbind every key in [lo, hi) and return the removed bindings, clipped to [lo, hi).
        """
        if lo >= hi:
            return []
        return self._splice(lo, hi, [])

    def __setitem__(self, key: int, value: V) -> None:
        self._splice(key, key + 1, [(key, key + 1, value)])

    def __delitem__(self, key: int) -> None:
        if not self._splice(key, key + 1, []):
            raise KeyError(key)

    def pop[TD](self, key: int, *default: TD) -> V | TD:
        removed = self._splice(key, key + 1, []) if key in self else []
        if removed:
            return removed[0][2]
        if default:
            return default[0]
        raise KeyError(key)

    def __repr__(self) -> str:
        return "<IntervalMapCOW " + ", ".join(f"[{s}, {e}): {v!r}" for s, e, v in self.segments()) + ">"
