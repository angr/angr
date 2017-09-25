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

        left_idx = self._search(this_item.start)
        right_idx = self._search(this_item.end)

        left_item = self._item_at(this_item.start)
        if left_item and left_idx == right_idx:
            right_item = left_item.copy()
        else:
            right_item = self._item_at(this_item.end)

        if left_item and left_item.end > this_item.start:
            self._merge_left(this_item, left_item)
            self._trim_right(left_item, this_item)

        if right_item and right_item.start <= this_item.end:
            self._merge_right(this_item, right_item)
            self._trim_left(right_item, this_item)
        else:
            right_item = None

        if not left_item and not right_item:
            self._list.insert(left_idx, this_item)
            return

        picked_items = filter(None, (left_item, this_item, right_item))
        mid_part = deque((i for i in picked_items if i.size > 0))

        left_split_idx = max(left_idx, 0)
        right_split_idx = min(right_idx + 1, len(self._list))

        while left_split_idx > 0 and mid_part:
            if self._merge_right(self._list[left_split_idx - 1], mid_part[0]):
                mid_part.popleft()
                continue
            break

        while mid_part and right_split_idx < len(self._list):
            if self._merge_left(self._list[right_split_idx], mid_part[-1]):
                mid_part.pop()
                continue
            break

        if not mid_part and left_split_idx > 0 and right_split_idx < len(self._list):
            if self._merge_right(self._list[left_split_idx - 1], self._list[right_split_idx]):
                right_split_idx += 1

        self._list[left_split_idx:right_split_idx] = mid_part

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

    def _trim_left(self, this_item, left_item):
        this_item.start = left_item.end
        return True

    def _trim_right(self, this_item, right_item):
        this_item.end = right_item.start
        return True

    def _merge_left(self, this_item, left_item):
        if self._should_merge(this_item, left_item):
            return self._try_merge_left(this_item, left_item)
        return False

    def _merge_right(self, this_item, right_item):
        if self._should_merge(this_item, right_item):
            return self._try_merge_right(this_item, right_item)
        return False

    def _should_merge(self, this_item, other_item):
        return this_item.value == other_item.value

    def _try_merge_left(self, this_item, left_item):
        if this_item.start <= left_item.end:
            this_item.start = left_item.start
            return True
        return False

    def _try_merge_right(self, this_item, right_item):
        if this_item.end >= right_item.start:
            this_item.end = right_item.end
            return True

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
