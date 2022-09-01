import threading


class PicklableLock:
    """
    Normal thread-locks are not pickleable. This provides a pickleable lock by mandating that the lock is unlocked
    during serialization.
    """
    _LOCK = threading.Lock

    def __init__(self, *args, **kwargs):
        self._lock = self.__class__._LOCK(*args, **kwargs)  # pylint: disable=too-many-function-args

    def __enter__(self):
        return self._lock.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._lock.__exit__(exc_type, exc_val, exc_tb)

    def acquire(self, *args, **kwargs):
        return self._lock.acquire(*args, **kwargs)

    def locked(self):
        return self._lock.locked()

    def release(self):
        return self._lock.release()

    def __reduce__(self):
        if self.locked():
            raise TypeError("Why are you pickling a locked lock")
        return type(self), ()


class PicklableRLock(PicklableLock):
    """
    Same as above, but uses RLock instead of Lock for locking. Note that RLock does not provide an interface to tell
    whether is it presently held by any thread, and thus this class will lie about whether it is locked.
    """
    _LOCK = threading.RLock

    def locked(self):
        return False   # ummmmmmmmmmmmmmmm
