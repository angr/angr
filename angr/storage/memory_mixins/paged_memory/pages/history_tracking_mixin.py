from angr.storage.memory_mixins import MemoryMixin


class HistoryTrackingMixin(MemoryMixin):
    """
    Tracks the history of memory writes.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._parent = None
        self._changed_offsets = set()

    def store(self, addr, data, **kwargs):
        self._changed_offsets.add(addr)
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
