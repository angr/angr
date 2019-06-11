import claripy
from ..errors import SimMemoryError


def obj_bit_size(o):
    if type(o) is bytes:
        return len(o) * 8
    return o.size()


class SimMemoryObject(object):
    """
    A MemoryObjectRef instance is a reference to a byte or several bytes in
    a specific object in SimSymbolicMemory. It is only used inside
    SimSymbolicMemory class.
    """
    def __init__(self, obj, base, length=None, byte_width=8):
        if type(obj) is bytes:
            assert byte_width == 8

        elif not isinstance(obj, claripy.ast.Base):
            raise SimMemoryError('memory can only store claripy Expression')

        self.is_bytes = type(obj) == bytes
        self._byte_width = byte_width
        self.base = base
        self.object = obj
        self.length = obj_bit_size(obj) // self._byte_width if length is None else length

    def size(self):
        return self.length * self._byte_width

    def __len__(self):
        return self.size()

    @property
    def last_addr(self):
        return self.base + self.length - 1

    def includes(self, x):
        return 0 <= x - self.base < self.length

    def bytes_at(self, addr, length, allow_concrete=False):
        if addr == self.base and length == self.length:
            return claripy.BVV(self.object) if not allow_concrete and self.is_bytes else self.object

        if self.is_bytes:
            start = addr - self.base
            end = start + length
            o = self.object[start:end]
            return o if allow_concrete else claripy.BVV(o)
        obj_size = self.size()
        left = obj_size - (addr-self.base)*self._byte_width - 1
        right = left - length*self._byte_width + 1
        return self.object[left:right]

    def _object_equals(self, other):
        if self.is_bytes != other.is_bytes:
            return False

        if self.is_bytes:
            return self.object == other.object
        else:
            return self.object.cache_key == other.object.cache_key

    def _length_equals(self, other):
        if type(self.length) != type(other.length):
            return False

        if type(self.length) is int:
            return self.length == other.length
        else:
            return self.length.cache_key == other.length.cache_key

    def __eq__(self, other):
        if type(other) is not SimMemoryObject:
            return NotImplemented

        return  self.base == other.base and \
                self._object_equals(other) and \
                self._length_equals(other)

    def __hash__(self):
        obj_hash = hash(self.object) if self.is_bytes else self.object.cache_key
        return hash((obj_hash, self.base, hash(self.length)))

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "MO(%s)" % self.object
