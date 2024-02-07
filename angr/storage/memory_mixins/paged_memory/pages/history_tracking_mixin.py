# pylint:disable=arguments-differ,unused-argument,no-member
from typing import Set, Optional

from angr.storage.memory_mixins import MemoryMixin
from angr.utils.segment_list import SegmentList
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
        o = super().copy(memo)
        return o

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

    def changed_bytes(self, other, **kwargs) -> Optional[Set[int]]:
        candidates: Set[int] = set()

        self_history_list = [self] + list(self.parents())
        other_history_list = [other] + list(other.parents())
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

            for page_ in self_history_list[: i + 1]:
                for seg in page_._changed_offsets._list:
                    candidates.update(range(seg.start, seg.end))
            for page_ in other_history_list[: j + 1]:
                for seg in page_._changed_offsets._list:
                    candidates.update(range(seg.start, seg.end))
            return candidates

        return None

    def all_bytes_changed_in_history(self) -> SegmentList:
        changed_bytes: SegmentList = self._changed_offsets.copy()

        mem = self._parent
        while mem is not None:
            for seg in mem._changed_offsets._list:
                changed_bytes.occupy(seg.start, seg.end - seg.start, DUMMY_SORT)
            mem = mem._parent
        return changed_bytes
