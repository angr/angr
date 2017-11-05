import claripy
from ..errors import SimMemoryError

class SimMemoryObject(object):
    """
    A MemoryObjectRef instance is a reference to a byte or several bytes in
    a specific object in SimSymbolicMemory. It is only used inside
    SimSymbolicMemory class.
    """
    def __init__(self, object, base, length=None, byte_width=8): #pylint:disable=redefined-builtin
        if not isinstance(object, claripy.ast.Base):
            raise SimMemoryError('memory can only store claripy Expression')
        self._byte_width = byte_width
        self._base = base
        self._object = object
        self._length = object.size()//self._byte_width if length is None else length

    def size(self):
        return self._length * self._byte_width

    def __len__(self):
        return self.size()

    @property
    def base(self):
        return self._base

    @property
    def length(self):
        return self._length

    @property
    def last_addr(self):
        return self._base + self._length - 1

    def includes(self, x):
        return 0 <= x - self._base < self._length

    @property
    def object(self):
        return self._object

    def bytes_at(self, addr, length):
        if addr == self.base and length == self.length:
            return self.object

        obj_size = self.size()
        left = obj_size - (addr-self.base)*self._byte_width - 1
        right = left - length*self._byte_width + 1
        return self.object[left:right]

    def __eq__(self, other):
        if type(other) is not SimMemoryObject:
            return NotImplemented

        return self._object is other._object and self._base == other._base and hash(self._length) == hash(other._length)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "MO(%s)" % (self.object)
