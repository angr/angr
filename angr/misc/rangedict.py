from collections import deque


class RangeItem(object):

    def __init__(self, start, end, value):
        self.start = start
        self.end = end
        self.value = value

    def __repr__(self):
        return '<RangeKey(%s, %s, %s)>' % (self.start, self.end, self.value)

    @property
    def size(self):
        return self.end - self.start

    def occupies_pos(self, pos):
        return self.start <= pos < self.end

    def copy(self):
        return RangeItem(self.start, self.end, self.value)


class RangeDict(object):

    def __init__(self):
        self._list = []

    def __getitem__(self, key):
        if isinstance(key, int):
            item = self._item_at(key)
            if item is None:
                raise KeyError(key)
            return item.value
        elif not isinstance(key, slice):
            raise TypeError(key)

        start, end = self._make_range(key)
        return [item.value for item in self.islice(start, end)]

    def __setitem__(self, key, value):
        start, end = self._make_range(key)
        if start == end:
            return

        this_item = self._make_item(start, end, value)
        picked_items = deque([this_item])

        left_idx = self._search(this_item.start)
        right_idx = self._search(this_item.end)

        orig_left_idx = left_idx
        while 0 <= left_idx < len(self._list):
            left_item = self._list[left_idx]
            if this_item.start < left_item.start:
                left_idx -= 1
                continue
            if self._adjoin_left(this_item, left_item):
                if left_idx == right_idx:
                    left_item = left_item.copy()
                if self._should_merge(this_item, left_item):
                    self._merge_left(this_item, left_item)
                self._trim_right(left_item, this_item)
                picked_items.appendleft(left_item)
                left_idx -= 1
                continue
            elif left_idx < orig_left_idx:
                picked_items.appendleft(left_item)
            break

        orig_right_idx = right_idx
        while 0 <= right_idx < len(self._list):
            right_item = self._list[right_idx]
            if this_item.end > right_item.end:
                right_idx += 1
                continue
            if self._adjoin_right(this_item, right_item):
                if self._should_merge(this_item, right_item):
                    self._merge_right(this_item, right_item)
                self._trim_left(right_item, this_item)
                picked_items.append(right_item)
                right_idx += 1
                continue
            elif right_idx > orig_right_idx:
                picked_items.append(right_item)
            break

        left_idx, right_idx = max(left_idx, 0), min(right_idx, len(self._list))
        self._list[left_idx:right_idx] = (i for i in picked_items if i.size > 0)

    def __len__(self):
        return len(self._list)

    def __contains__(self, key):
        return self._item_at(key) is not None

    def __iter__(self):
        return iter(self._list)

    #
    #   ...
    #

    def peekitem(self, k, default=None):
        item = self._item_at(k)
        if item is not None:
            return item
        return default

    def islice(self, start=None, end=None):
        if self._list:
            start = start if start is not None else 0
            end = end if end is not None else self._list[-1].end
            for item in self._list[self._search(start):]:
                if item.start >= end:
                    break
                yield item

    #
    #   ...
    #

    def _search(self, pos):
        lo = 0
        hi = len(self._list)

        while lo != hi:
            mid = (lo + hi) / 2

            item = self._list[mid]
            if pos < item.start:
                hi = mid
            elif pos >= item.end:
                lo = mid + 1
            else:
                lo = mid
                break

        return lo

    def _item_at(self, pos):
        idx = self._search(pos)
        if idx < len(self._list) and self._list[idx].occupies_pos(pos):
            return self._list[idx]

    def _adjoin_left(self, this_item, left_item):
        return left_item.start <= this_item.start <= left_item.end

    def _adjoin_right(self, this_item, right_item):
        return right_item.end >= this_item.end >= right_item.start

    def _should_merge(self, this_item, other_item):
        return this_item.value == other_item.value

    def _trim_left(self, this_item, left_item):
        this_item.start = left_item.end

    def _trim_right(self, this_item, right_item):
        this_item.end = right_item.start

    def _merge_left(self, this_item, left_item):
        this_item.start = left_item.start

    def _merge_right(self, this_item, right_item):
        this_item.end = right_item.end

    def _make_item(self, start, end, value):
        return RangeItem(start, end, value)

    @staticmethod
    def _make_range(key):
        if isinstance(key, slice):
            if key.step is not None:
                raise ValueError(key.step)
            return key.start, key.stop
        elif isinstance(key, int):
            return key, key + 1
        else:
            raise TypeError(key)
