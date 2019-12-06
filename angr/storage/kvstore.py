
from .memory import SimMemory


class TypedVariable:

    __slots__ = ['type', 'value']

    def __init__(self, type_, value):
        self.type = type_
        self.value = value


class SimKVStore(SimMemory):
    def __init__(self, store=None):
        super(SimKVStore, self).__init__()

        self._store = {  } if store is None else store

    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None,
             inspect=True, disable_actions=False, ret_on_segv=False, none_if_missing=False):
        key = addr
        if none_if_missing and key not in self._store:
                return None
        return self._store[key].value

    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None,
              inspect=True, priv=None, disable_actions=False, type_=None):

        if self.id == "mem":
            assert type_ is not None

        key = addr
        self._store[key] = TypedVariable(type_, data)

    def copy(self):
        return SimKVStore(store=self._store.copy())

    def __str__(self):
        return "\n".join(["%s: %s (%s)" % (k, v.value, v.type) for k,v in self._store.items()])

