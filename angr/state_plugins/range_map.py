import bisect
import math


class RangeMap(object):

    PAGE_SIZE = 4096
    CUTOFF_RANGE_SIZE = 3

    def __init__(self, large_ranges=[], ranges={}, size=0):
        self._large_ranges = large_ranges
        self._ranges = ranges
        self._cowed = set()
        self._size = size

    def add(self, start, end, obj):

        self._size += 1

        begin = int(start / RangeMap.PAGE_SIZE)
        finish = int(math.ceil(end / RangeMap.PAGE_SIZE))

        if end - begin >= RangeMap.CUTOFF_RANGE_SIZE:
            self._large_ranges.append((start, end, obj))

        else:

            index = begin
            t = (start, end, obj)
            while index <= finish:

                if index not in self._ranges:
                    page = [t, ]
                    self._ranges[index] = page
                    self._cowed.add(index)

                else:

                    if index not in self._cowed:
                        self._ranges[index] = list(self._ranges[index])
                        self._cowed.add(index)

                    self._ranges[index].append(t)

                index += 1

    def query(self, start, end):

        result = []

        for r in self._large_ranges:
            if self._intersect(start, end, r[0], r[1]):
                self._insert_if_not_in(result, r)


        begin = int(start / RangeMap.PAGE_SIZE)
        finish = int(math.ceil(end / RangeMap.PAGE_SIZE))

        if end - begin < self.CUTOFF_RANGE_SIZE:

            index = begin
            while index <= finish:

                if index in self._ranges:
                    for r in self._ranges[index]:
                        if self._intersect(start, end, r[0], r[1]):
                            self._insert_if_not_in(result, r)

                index += 1

        else:

            indexes = sorted(self._ranges.keys())
            k = bisect.bisect_left(indexes, begin)

            while k < len(indexes) and indexes[k] <= finish:

                index = indexes[k]
                for r in self._ranges[index]:
                    if self._intersect(start, end, r[0], r[1]):
                        self._insert_if_not_in(result, r)

                k += 1

        return result

    def remove(self, r):

        # r must be returned by query()

        pos = self._find_by_id(self._large_ranges, id(r))
        if pos is not None:
            self._large_ranges.pop(pos)
            return

        begin = int(r[0] / RangeMap.PAGE_SIZE)
        finish = int(math.ceil(r[1] / RangeMap.PAGE_SIZE))

        index = begin
        while index <= finish:

            if index in self._ranges:
                pos = self._find_by_id(self._ranges[index], id(r))
                if pos is not None:
                    self._ranges[index].pop(pos)

            index += 1

        self._size -= 1

    def replace(self, old, new):

        # old must be returned by query()
        assert old[0] == new[0] and old[1] == new[1]

        pos = self._find_by_id(self._large_ranges, id(old))
        if pos is not None:
            self._large_ranges[pos] = new
            return

        begin = int(new[0] / RangeMap.PAGE_SIZE)
        finish = int(math.ceil(new[1] / RangeMap.PAGE_SIZE))

        index = begin
        while index <= finish:

            if index in self._ranges:
                pos = self._find_by_id(self._ranges[index], id(old))
                if pos is not None:
                    self._ranges[index][pos] = new

            index += 1


    def _intersect(self, a_min, a_max, b_min, b_max):

        if b_min <= a_min <= b_max:
            return True

        if a_min <= b_min <= a_max:
            return True

        if b_min <= a_max <= b_max:
            return True

        if a_min <= b_max <= a_max:
            return True

        return False

    def _find_by_id(self, list, obj_id):
        for k in range(len(list)):
            o = list[k]
            if id(o) == obj_id:
                return k
        return None

    def _insert_if_not_in(self, list, obj):
        for k in range(len(list)):
            o = list[k]
            if id(o) == id(obj):
                return
        list.append(obj)

    def copy(self):
        rm = RangeMap(list(self._large_ranges), dict(self._ranges), self._size)
        return rm

    def merge(self, others, merge_conditions):

        for o in others:
            self._large_ranges |= o._large_ranges

        assert False # ToDo

    def __len__(self):
        return self._size


