from __future__ import annotations

from angr.storage.memory_mixins.memory_mixin import MemoryMixin


class TypedVariable:
    """TypedVariable is a simple class that holds a value and a type."""

    __slots__ = (
        "type",
        "value",
    )

    def __init__(self, type_, value):
        self.type = type_
        self.value = value


class KeyValueMemoryMixin(MemoryMixin):
    """KeyValueMemoryMixin is a mixin that provides a simple key-value store for memory."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._store = {}

    def load(self, addr, size=None, none_if_missing=False, **kwargs):  # pylint: disable=unused-argument
        if none_if_missing and addr not in self._store:
            return None
        return self._store[addr].value

    def store(self, addr, data, type_=None, **kwargs):
        self._store[addr] = TypedVariable(type_, data)

    @MemoryMixin.memo
    def copy(self, memo):
        o: KeyValueMemoryMixin = super().copy(memo)
        o._store = self._store.copy()
        return o

    def __str__(self):
        return "\n".join([f"{k}: {v.value} ({v.type})" for k, v in self._store.items()])
