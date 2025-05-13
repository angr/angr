# pylint:disable=arguments-differ,unused-argument,no-member
from __future__ import annotations

from angr.storage.memory_mixins.memory_mixin import MemoryMixin
from angr.rustylib import SegmentList
from .refcount_mixin import RefcountMixin


MAX_HISTORY_DEPTH = 50
DUMMY_SORT = ""


class HistoryTrackingMixin(RefcountMixin, MemoryMixin):
    """
    Tracks the history of memory writes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._parent = None
        self._history_depth = 0
        self._changed_offsets: SegmentList = SegmentList()

    def store(self, addr, data, size=None, **kwargs):
        if size > 0:
            self._changed_offsets.occupy(addr, size, DUMMY_SORT)
        return super().store(addr, data, **kwargs)

    def copy(self, memo):
        return super().copy(memo)

    def acquire_unique(self):
        page = super().acquire_unique()
        if page is not self:
            page._history_depth = self._history_depth + 1
            if page._history_depth > MAX_HISTORY_DEPTH:
                # collapse
                page._changed_offsets = self.all_bytes_changed_in_history()
                page._parent = None
                page._history_depth = 0
            else:
                page._parent = self
                page._changed_offsets = SegmentList()
        return page

    def parents(self):
        parent = self._parent
        while parent is not None:
            yield parent
            parent = parent._parent

    def changed_bytes(self, other, **kwargs) -> set[int] | None:
        candidates = SegmentList()

        self_history_list = [self, *list(self.parents())]
        other_history_list = [other, *list(other.parents())]
        if self_history_list and other_history_list and self_history_list[-1] is other_history_list[-1]:
            # two pages have the same root. we can get a list of candidate offsets this way

            # find the common ancestor
            i = len(self_history_list) - 1
            j = len(other_history_list) - 1
            while i >= 0 and j >= 0:
                if self_history_list[i] is not other_history_list[j]:
                    break
                i -= 1
                j -= 1

            for page in self_history_list[: i + 1]:
                candidates.update(page._changed_offsets)
            for page in other_history_list[: j + 1]:
                candidates.update(page._changed_offsets)

            # Convert to a set of indices. This can be super slow if the ranges are
            # large!
            candidate_set = set()

            for offset in candidates:
                candidate_set.update(range(offset.start, offset.end))

            return candidate_set

        return None

    def all_bytes_changed_in_history(self) -> SegmentList:
        changed_bytes: SegmentList = self._changed_offsets.copy()

        mem = self._parent
        while mem is not None:
            changed_bytes.update(mem._changed_offsets)
            mem = mem._parent
        return changed_bytes
