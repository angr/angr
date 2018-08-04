import claripy
from ..errors import SimMemoryError


class SimMemoryObject(object):
    """
    A MemoryObjectRef instance is a reference to a byte or several bytes in
    a specific object in SimSymbolicMemory. It is only used inside
    SimSymbolicMemory class.
    """
    def __init__(self, obj, base, length=None, byte_width=8):
        if not isinstance(obj, claripy.ast.Base):
            raise SimMemoryError('memory can only store claripy Expression')
        self._byte_width = byte_width
        self.base = base
        self.object = obj
        self.length = obj.size()//self._byte_width if length is None else length

    def size(self):
        return self.length * self._byte_width

    def __len__(self):
        return self.size()

    @property
    def last_addr(self):
        return self.base + self.length - 1

    def includes(self, x):
        return 0 <= x - self.base < self.length

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

        return self.object.cache_key == other.object.cache_key and \
               self.base == other.base and \
               (self.length == other.length if type(self.length) is int
                else False if type(other.length) != int
                else self.length.cache_key == other.length.cache_key)

    def __hash__(self):
        return hash((self.object.cache_key, self.base, hash(self.length)))

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "MO(%s)" % self.object
