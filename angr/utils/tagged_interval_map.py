from __future__ import annotations
from collections.abc import Iterator

from sortedcontainers import SortedDict


class TaggedIntervalMap:
    """
    Catalogs features of intervals.
    """

    def __init__(self, nbits: int = 0):
        """
        :param nbits: Number of binning bits. Higher values reduce detail. 0 for no binning.
        """
        self._nbits: int = nbits
        self._map: SortedDict = SortedDict()  # SortedDict[int, int]

    @property
    def nbits(self) -> int:
        return self._nbits

    def add(self, addr: int, size: int, tags: int) -> None:
        """
        Add interval starting at `addr` of `size` bytes.

        When binning, intervals endpoints are aligned to 2^nbits. Gaps between added intervals are populated with
        implicit intervals having tag value of 0. Overlapping intervals will have tag bits OR'd together.

        Adjacent intervals in the interval map have unique tags. When intervals are added to the map, any adjacent stops
        with identical tags will be eliminated so the map retains this property.

        For example: if an interval(addr=0, size=100, tags=1) is added, followed by (100, 100, 1), the resulting
        interval in the map will be (0, 200, 1).
        """
        assert addr >= 0
        assert size >= 0
        assert tags != 0

        if size == 0:
            return

        max_bin_offset = (1 << self._nbits) - 1
        mask = ~max_bin_offset

        start_addr = addr & mask  # Round down to bin alignment
        end_addr = (addr + size + max_bin_offset) & mask  # Round up to bin alignment

        if self._is_already_covered(start_addr, end_addr, tags):
            return

        self._insert_stop(start_addr)
        self._insert_stop(end_addr)
        for affected_addr in self._map.irange(start_addr, end_addr, inclusive=(True, False)):
            self._map[affected_addr] |= tags
        self._eliminate_extraneous_stops(start_addr, end_addr)

    def _insert_stop(self, addr: int) -> None:
        """
        Insert a new interval stop point at `addr`, if one is not already present in the map. Tags are copied from
        nearest stop before `addr`.
        """
        if addr not in self._map:
            idx = self._map.bisect(addr) - 1
            self._map[addr] = self._map.peekitem(idx)[1] if idx >= 0 else 0

    def _is_already_covered(self, min_addr: int, end_addr: int, tags: int) -> bool:
        """
        Determine if interval [min_addr, end_addr) is covered by an existing range with identical tags.
        """
        idx = self._map.bisect(min_addr) - 1
        if idx >= 0 and len(self._map) > idx + 1:
            e_addr, e_tags = self._map.peekitem(idx)
            e_addr_next, _ = self._map.peekitem(idx + 1)
            return (e_addr <= min_addr) and (end_addr <= e_addr_next) and (e_tags == tags)
        return False

    def _eliminate_extraneous_stops(self, min_addr: int, max_addr: int) -> None:
        """
        Canonicalize the map by eliminating adjacent stops with identical tags both inside and directly outside of
        [min_addr, max_addr].
        """
        keys_to_drop = []
        prev_tags = None
        for addr, _, tags in self.irange(min_addr, max_addr):
            if tags == prev_tags:
                keys_to_drop.append(addr)
            else:
                prev_tags = tags

        for addr in keys_to_drop:
            del self._map[addr]

    def irange(self, min_addr: int | None = None, max_addr: int | None = None) -> Iterator[tuple[int, int, int]]:
        """
        Iterate over intervals intersecting [min_addr, max_addr], yielding interval (addr, size, tags) tuples. Implicit
        gap intervals (with tags=0) are also returned.

        :param min_addr: Minimum address (inclusive) to begin iterating from. If None, iterate from start of map.
        :param max_addr: Maximum address (inclusive) to iterate to. If None, iterate to end of map.
        """
        if not self._map:
            return

        start_idx = 0 if min_addr is None else max(0, self._map.bisect_left(min_addr) - 1)
        stop_idx = None if max_addr is None else (self._map.bisect(max_addr) + 1)

        start_addr, tags = self._map.peekitem(start_idx)
        for addr in self._map.islice(start_idx + 1, stop_idx):
            yield (start_addr, addr - start_addr, tags)
            tags = self._map[addr]
            start_addr = addr
