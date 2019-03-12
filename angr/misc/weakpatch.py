from weakref import WeakValueDictionary, WeakKeyDictionary, _IterationGuard

def copy_wvd(self):
    if self._pending_removals:
        self._commit_removals()
    new = WeakValueDictionary()
    with _IterationGuard(self):
        for key, wr in self.data.items():
            o = wr()
            if o is not None:
                new[key] = o
    return new

def deepcopy_wvd(self, memo):
    from copy import deepcopy
    if self._pending_removals:
        self._commit_removals()
    new = self.__class__()
    with _IterationGuard(self):
        for key, wr in self.data.items():
            o = wr()
            if o is not None:
                new[deepcopy(key, memo)] = o
    return new

def copy_wkd(self):
    new = WeakKeyDictionary()
    with _IterationGuard(self):
        for key, value in self.data.items():
            o = key()
            if o is not None:
                new[o] = value
    return new

def deepcopy_wkd(self, memo):
    from copy import deepcopy
    new = self.__class__()
    with _IterationGuard(self):
        for key, value in self.data.items():
            o = key()
            if o is not None:
                new[o] = deepcopy(value, memo)
    return new

WeakValueDictionary.copy = copy_wvd
WeakValueDictionary.__copy__ = copy_wvd
WeakValueDictionary.__deepcopy__ = deepcopy_wvd

WeakKeyDictionary.copy = copy_wkd
WeakKeyDictionary.__copy__ = copy_wkd
WeakKeyDictionary.__deepcopy__ = deepcopy_wkd
