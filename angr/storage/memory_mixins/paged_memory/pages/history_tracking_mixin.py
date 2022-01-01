from typing import Set, Optional

from angr.storage.memory_mixins import MemoryMixin


class HistoryTrackingMixin(MemoryMixin):
    """
    Tracks the history of memory writes.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._parent = None
        self._changed_offsets = set()

    def store(self, addr, data, size=None, **kwargs):
        for i in range(size):
            self._changed_offsets.add(addr + i)
        return super().store(addr, data, **kwargs)

    def copy(self, memo):
        o = super().copy(memo)
        o._parent = self
        o._changed_offsets = set()
        return o

    def parents(self):
        parent = self._parent
        while parent is not None:
            yield parent
            parent = parent._parent

    def changed_bytes(self, other) -> Optional[Set[int]]:
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

            for page_ in self_history_list[:i+1]:
                candidates |= page_._changed_offsets
            for page_ in other_history_list[:j+1]:
                candidates |= page_._changed_offsets
            return candidates

        return None
