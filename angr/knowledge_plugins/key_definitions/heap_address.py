from typing import Union

from .undefined import Undefined


class HeapAddress:
    """
    The representation of an address on the heap.
    """
    def __init__(self, value: Union[int,Undefined]):
        self._value = value

    @property
    def value(self): return self._value

    def __repr__(self):
        address_as_string = ("%#x" % self._value) if isinstance(self._value, int) else ("%s" % self._value)
        return "HeapAddress<%s>" % address_as_string
