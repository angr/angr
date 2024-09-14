from __future__ import annotations
from .undefined import Undefined


class HeapAddress:
    """
    The representation of an address on the heap.
    """

    def __init__(self, value: int | Undefined):
        self._value = value

    @property
    def value(self):
        return self._value

    def __repr__(self):
        address_as_string = (f"{self._value:#x}") if isinstance(self._value, int) else (f"{self._value}")
        return f"HeapAddress<{address_as_string}>"

    def __add__(self, value):
        if not isinstance(value, int):
            raise TypeError(f"Can only add int to HeapAddress, got {type(value).__name__}")
        return HeapAddress(self.value + value)

    def __radd__(self, value):
        return self.__add__(value)

    def __eq__(self, other):
        return isinstance(other, HeapAddress) and self._value == other._value

    def __hash__(self):
        return hash(self._value)
