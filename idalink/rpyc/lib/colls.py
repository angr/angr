import weakref
from threading import Lock

class WeakValueDict(object):
    """a light-weight version of weakref.WeakValueDictionary"""
    __slots__ = ("_dict",)
    def __init__(self):
        self._dict = {}
    def __repr__(self):
        return repr(self._dict)
    def __iter__(self):
        return self.iterkeys()
    def __len__(self):
        return len(self._dict)
    def __contains__(self, key):
        try:
            self[key]
        except KeyError:
            return False
        else:
            return True
    def get(self, key, default = None):
        try:
            return self[key]
        except KeyError:
            return default
    def __getitem__(self, key):
        obj = self._dict[key]()
        if obj is None:
            raise KeyError(key)
        return obj
    def __setitem__(self, key, value):
        def remover(wr, _dict = self._dict, key = key):
            _dict.pop(key, None)
        self._dict[key] = weakref.ref(value, remover)
    def __delitem__(self, key):
        del self._dict[key]
    def iterkeys(self):
        return self._dict.keys()
    def keys(self):
        return self._dict.keys()
    def itervalues(self):
        for k in self:
            yield self[k]
    def values(self):
        return list(self.itervalues())
    def iteritems(self):
        for k in self:
            yield k, self[k]
    def items(self):
        return list(self.iteritems())
    def clear(self):
        self._dict.clear()

class RefCountingColl(object):
    """a set-like object that implements refcounting on its contained objects"""
    __slots__ = ("_lock", "_dict")
    def __init__(self):
        self._lock = Lock()
        self._dict = {}
    def __repr__(self):
        return repr(self._dict)
    def add(self, obj):
        self._lock.acquire()
        try:
            key = id(obj)
            slot = self._dict.get(key, None)
            if slot is None:
                slot = [obj, 0]
            else:
                slot[1] += 1
            self._dict[key] = slot
        finally:
            self._lock.release()
    def clear(self):
        self._lock.acquire()
        try:
            self._dict.clear()
        finally:
            self._lock.release()
    def decref(self, key):
        self._lock.acquire()
        try:
            slot = self._dict[key]
            if slot[1] < 1:
                del self._dict[key]
            else:
                slot[1] -= 1
                self._dict[key] = slot
        finally:
            self._lock.release()
    def __getitem__(self, key):
        self._lock.acquire()
        try:
            return self._dict[key][0]
        finally:
            self._lock.release()

