from __future__ import annotations

from typing import Generic, TypeVar

from sortedcontainers import SortedDict


K = TypeVar("K")
V = TypeVar("V")


class RangeSetMapEntry:
    """
    An entry in a RangeSetMap, consisting of a range and a set of values.
    """

    __slots__ = ("end", "start", "values")

    def __init__(self, start: int, end: int, values: set):
        self.start = start
        self.end = end  # exclusive
        self.values = values


class RangeSetMap(Generic[K, V]):
    """
    A mapping from ranges to sets of values. Ranges are non-overlapping and sorted, so we can query them using irange()
    efficiently.
    """

    __slots__ = ("_map",)

    def __init__(self, other: RangeSetMap | None = None):
        self._map = SortedDict(other._map) if other is not None else SortedDict()

    def prior_key(self, key: int) -> int | None:
        """
        Get the key whose range starts at or before the given key, or None if no such entry exists.
        """
        try:
            prior_key = next(self._map.irange(maximum=key, reverse=True))
        except StopIteration:
            return None
        return prior_key

    def next_key(self, key: int) -> int | None:
        """
        Get the key whose range starts at or after the given key, or None if no such entry exists.
        """
        try:
            next_key = next(self._map.irange(minimum=key))
        except StopIteration:
            return None
        return next_key

    def add(self, start: int, end: int, values: set[V]):
        """
        Add a value to the set of values associated with the given range. Any overlapping ranges will be overwritten.
        """
        if start >= end:
            raise ValueError("Invalid range: start must be less than end")

        # Create the new entry
        entry = RangeSetMapEntry(start, end, values)

        # Eliminate any overlapping entries

        # front
        prior_key = self.prior_key(start)
        if prior_key is not None:
            prior_entry = self._map[prior_key]
            if prior_entry.end > start:
                # overlapping! adjust the prior entry to end at the start of the new entry
                prior_item = self._map[prior_key]
                del self._map[prior_key]
                if prior_key < start:
                    self._map[prior_key] = RangeSetMapEntry(prior_key, start, prior_item.values)

        # back
        try:
            all_keys = list(self._map.irange(minimum=start, maximum=end, inclusive=(True, False)))
        except StopIteration:
            all_keys = []
        for next_key in all_keys:
            next_entry = self._map[next_key]
            if next_entry.start < end:
                # overlapping! adjust the next entry to start at the end of the new entry
                next_item = self._map[next_key]
                del self._map[next_key]
                if next_entry.end > end:
                    self._map[end] = RangeSetMapEntry(end, next_entry.end, next_item.values)

        # write the new entry
        self._map[start] = entry

    def add_value(self, start: int, end: int, value: V):
        """
        Add a value to the set of values associated with the given range.
        """
        existing_values = self.get(start, set())
        self.add(start, end, existing_values | {value})

    def __contains__(self, k: K) -> bool:
        """
        Return True if the given key is contained in any of the ranges in the map.
        """
        prior_key = self.prior_key(k)
        if prior_key is None:
            return False
        prior_entry = self._map[prior_key]
        return prior_entry.end > k

    def __getitem__(self, k: K) -> set[V]:
        """
        Get the set of values associated with the given key, or raise KeyError if no such entry exists.
        """
        prior_key = self.prior_key(k)
        if prior_key is None:
            raise KeyError(k)
        prior_entry = self._map[prior_key]
        if prior_entry.end <= k:
            raise KeyError(k)
        return prior_entry.values

    def get(self, key: K, default: set[V] | None = None) -> set[V] | None:
        """
        Get the set of values associated with the given key, or return default if no such entry exists.
        """
        prior_key = self.prior_key(key)
        if prior_key is None:
            return default
        prior_entry = self._map[prior_key]
        if prior_entry.end <= key:
            return default
        return prior_entry.values

    def items(self, start_key: K, end_key: K, default):

        prior_key = self.prior_key(start_key)
        if prior_key is None:
            # start key is not contained...
            next_key = self.next_key(start_key)
            if next_key is None:
                # no entries at all?
                yield start_key, end_key, default
                return
            else:
                yield start_key, next_key, default
            prior_key = next_key

        last_entry: RangeSetMapEntry | None = None
        for k in self._map.irange(minimum=prior_key, maximum=end_key, inclusive=(True, False)):
            entry = self._map[k]
            if last_entry is not None:  # noqa: SIM102
                # are there gaps?
                if last_entry.end < min(entry.start, end_key):
                    yield last_entry.end, min(entry.start, end_key), default
            last_entry = entry
            yield max(start_key, entry.start), min(end_key, entry.end), entry.values

    def pop(self, key: int, default: V | None = None) -> set[V] | None:
        """
        Pop the entry associated with the given key, returning its set of values, or None if no such entry exists.
        """

        # find the entry containing the key
        prior_key = self.prior_key(key)
        if prior_key is None:
            return default
        prior_entry = self._map[prior_key]
        if prior_entry.end <= key:
            return default

        # adjust the prior entry to end at the key, and create a new entry after the key with the same values
        del self._map[prior_key]
        if prior_key < key:
            self._map[prior_key] = RangeSetMapEntry(prior_key, key, prior_entry.values)
        if prior_entry.end > key + 1:
            self._map[key + 1] = RangeSetMapEntry(key + 1, prior_entry.end, prior_entry.values)
        return prior_entry.values

    def to_dict(self) -> dict[int, set[V]]:
        """
        Convert the RangeSetMap to a regular dict mapping from range starts to sets of values. Note that this will lose
        the end information, so it should only be used for debugging purposes.
        """
        d = {}
        for _, v in self._map.items():
            for off in range(v.start, v.end):
                d[off] = set(v.values)
        return d

    def merge_with_check(self, other: RangeSetMap) -> bool:
        # correctness check
        d0 = self.to_dict()
        d1 = other.to_dict()

        for k, v in d1.items():
            if k not in d0:
                d0[k] = v
            else:
                d0[k] |= v

        r = self.merge(other)
        d2 = self.to_dict()
        if set(d0.keys()) != set(d2.keys()):
            raise RuntimeError
        for k in d0:
            if d0[k] != d2[k]:
                print(k)
                raise RuntimeError

        return r

    def merge(self, other: RangeSetMap) -> bool:
        """
        Merge another RangeSetMap into this one. Any overlapping ranges will be merged together.
        """

        if not other._map and not self._map:
            return False
        if not other._map:
            return False
        if not self._map:
            self._map = SortedDict(other._map)
            return True

        values = sorted(list(self._map.values()) + list(other._map.values()), key=lambda x: (x.start, x.end))

        map = SortedDict()
        last_k = None
        last_entry = None
        for i, v in enumerate(values):
            if i == 0:
                map[v.start] = v
                last_k = v.start
                last_entry = v
                continue

            if v.start < last_entry.end:
                # overlap found
                if last_entry.start < v.start:
                    map[last_k] = RangeSetMapEntry(last_entry.start, v.start, set(last_entry.values))
                if v.end <= last_entry.end:
                    # v is fully contained in last_entry
                    map[v.start] = RangeSetMapEntry(v.start, v.end, last_entry.values.union(v.values))
                    if v.end == last_entry.end:
                        last_k = v.start
                        last_entry = map[v.start]
                    elif v.end < last_entry.end:
                        next_part = RangeSetMapEntry(v.end, last_entry.end, set(last_entry.values))
                        map[v.end] = next_part
                        last_k = v.end
                        last_entry = next_part
                else:
                    # v extends beyond last_entry
                    map[v.start] = RangeSetMapEntry(v.start, last_entry.end, last_entry.values.union(v.values))
                    next_part = RangeSetMapEntry(last_entry.end, v.end, set(v.values))
                    map[last_entry.end] = next_part
                    last_k = last_entry.end
                    last_entry = next_part
            else:
                # no overlap, just add the entry
                map[v.start] = v
                last_k = v.start
                last_entry = v

        # compare to see if there were any changes
        if len(map) == len(self._map):
            for k, v in map.items():
                if k not in self._map:
                    break
                if self._map[k].start != v.start or self._map[k].end != v.end or self._map[k].values != v.values:
                    break
            else:
                # no changes
                return False

        self._map = map
        return True
