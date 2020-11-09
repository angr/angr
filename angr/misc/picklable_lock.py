import threading

class PicklableLock:
    def __init__(self):
        self._lock = threading.Lock()

    def __enter__(self):
        return self._lock.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._lock.__exit__(exc_type, exc_val, exc_tb)

    def acquire(self, blocking, timeout):
        return self._lock.acquire(blocking, timeout)

    def locked(self):
        return self._lock.locked()

    def release(self):
        return self._lock.release()

    def __reduce__(self):
        if self.locked():
            raise TypeError("Why are you pickling a locked lock")
        return type(self), ()
