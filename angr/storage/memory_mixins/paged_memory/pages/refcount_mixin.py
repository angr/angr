from __future__ import annotations
from angr.storage.memory_mixins import MemoryMixin
from angr.misc import PicklableLock


class RefcountMixin(MemoryMixin):
    """
    This mixin adds a locked reference counter and methods to manipulate it, to facilitate copy-on-write optimizations.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._init()

    def _init(self):
        self.refcount = 1
        self.lock = PicklableLock()

    def copy(self, memo):
        o = super().copy(memo)
        o._init()
        return o

    def acquire_unique(self):
        """
        Call this function to return a version of this page which can be used for writing, which may or may not
        be the same object as before. If you use this you must immediately replace the shared reference you previously
        had with the new unique copy.
        """
        with self.lock:
            if self.refcount == 1:
                return self
            self.refcount -= 1
        return self.copy(
            {}
        )  # TODO: evaluate if it's worth making the lock a reentrant lock (RLock) so this can go in the else arm

    def acquire_shared(self) -> None:
        """
        Call this function to indicate that this page has had a reference added to it and must be copied before it can
        be acquired uniquely again. Creating the object implicitly starts it with one shared reference.
        """
        with self.lock:
            self.refcount += 1

    def release_shared(self) -> None:
        """
        Call this function to indicate that this page has had a shared reference to it released
        """
        with self.lock:
            self.refcount -= 1
