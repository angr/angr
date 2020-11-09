from .. import MemoryMixin


class TypedVariable:

    __slots__ = ('type', 'value', )

    def __init__(self, type_, value):
        self.type = type_
        self.value = value


class KeyValueMemoryMixin(MemoryMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._store = { }

    def load(self, key, none_if_missing=False, **kwargs):
        if none_if_missing and key not in self._store:
            return None
        return self._store[key].value

    def store(self, key, data, type_=None, **kwargs):
        self._store[key] = TypedVariable(type_, data)

    @MemoryMixin.memo
    def copy(self, memo):
        o: 'KeyValueMemoryMixin' = super().copy(memo)
        o._store = self._store.copy()
        return o

    def __str__(self):
        return "\n".join(["%s: %s (%s)" % (k, v.value, v.type) for k,v in self._store.items()])
