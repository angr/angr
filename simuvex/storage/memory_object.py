import claripy
from ..s_errors import SimMemoryError

class SimMemoryObject(object):
    '''
    A MemoryObjectRef instance is a reference to a byte or several bytes in
    a specific object in SimSymbolicMemory. It is only used inside
    SimSymbolicMemory class.
    '''
    def __init__(self, object, base, length=None): #pylint:disable=redefined-builtin
        if not isinstance(object, claripy.Base):
            raise SimMemoryError('memory can only store claripy Expression')

        self._base = base
        self._object = object
        self._length = object.size()/8 if length is None else length

    def size(self):
        return self._length * 8

    def __len__(self):
        return self.size()

    @property
    def base(self):
        return self._base

    @property
    def length(self):
        return self._length

    @property
    def object(self):
        return self._object

    def bytes_at(self, addr, length):
        if addr == self.base and length == self.length:
            return self.object

        obj_size = self.size()
        left = obj_size - (addr-self.base)*8 - 1
        right = left - length*8 + 1
        return self.object[left:right]

    def __eq__(self, other):
        return self._object.identical(other._object) and self._base == other._base and hash(self._length) == hash(other._length)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "MO(%s)" % (self.object)

