import claripy

from ..errors import SimMemoryError


def obj_bit_size(o):
    if type(o) is bytes:
        return len(o) * 8
    return o.size()


# TODO: get rid of is_bytes and have the bytes-backed objects be a separate class


class SimMemoryObject:
    """
    A SimMemoryObject is a reference to a byte or several bytes in a specific object in memory. It should be used only
    by the bottom layer of memory.
    """

    __slots__ = (
        "is_bytes",
        "_byte_width",
        "base",
        "object",
        "length",
        "endness",
        "_concrete_bytes",
    )

    def __init__(self, obj, base, endness, length=None, byte_width=8):
        if type(obj) is bytes:
            assert byte_width == 8

        elif not isinstance(obj, claripy.ast.Base):
            raise SimMemoryError("memory can only store claripy Expression")

        self.is_bytes = type(obj) is bytes
        if self.is_bytes and endness != "Iend_BE":
            raise SimMemoryError("bytes can only be stored big-endian")
        self._byte_width = byte_width
        self.base = base
        self.object = obj
        self.length = obj_bit_size(obj) // self._byte_width if length is None else length
        self.endness = endness
        self._concrete_bytes: bytes | None = None

    def size(self):
        return self.length * self._byte_width

    def __len__(self):
        return self.size()

    @property
    def variables(self):
        return self.object.variables

    @property
    def cache_key(self):
        return self.object.cache_key

    @property
    def symbolic(self):
        return self.object.symbolic

    @property
    def last_addr(self):
        return self.base + self.length - 1

    def concrete_bytes(self, offset: int, size: int) -> bytes | None:
        if self._concrete_bytes is None:
            if isinstance(self.object, claripy.ast.Bits) and self.object.op == "BVV" and not self.object.annotations:
                self._concrete_bytes = self.object.concrete_value.to_bytes(len(self.object) // self._byte_width, "big")

        if self._concrete_bytes is None:
            return None

        return self._concrete_bytes[offset : offset + size]

    def includes(self, x):
        return 0 <= x - self.base < self.length

    def bytes_at(self, addr, length, allow_concrete=False, endness="Iend_BE"):
        rev = endness != self.endness
        if allow_concrete and rev:
            raise Exception("allow_concrete must be used with the stored endness")

        if self.is_bytes:
            if addr == self.base and length == self.length:
                o = self.object
            else:
                start = addr - self.base
                end = start + length
                o = self.object[start:end]

            return o if allow_concrete else claripy.BVV(o)

        else:
            offset = addr - self.base
            try:
                thing = bv_slice(self.object, offset, length, self.endness == "Iend_LE", self._byte_width)
            except claripy.ClaripyOperationError:
                # hacks to handle address space wrapping
                if offset >= 0:
                    raise
                if offset + 2**32 >= 0:
                    offset += 2**32
                elif offset + 2**64 >= 0:
                    offset += 2**64
                else:
                    raise
                thing = bv_slice(self.object, offset, length, self.endness == "Iend_LE", self._byte_width)

            if self.endness != endness:
                thing = thing.reversed
            return thing

    def _object_equals(self, other):
        if self.is_bytes != other.is_bytes:
            return False

        if self.is_bytes:
            return self.object == other.object
        else:
            return self.object.cache_key == other.object.cache_key

    def _length_equals(self, other):
        if type(self.length) is not type(other.length):  # noqa: E721
            return False

        if isinstance(self.length, int):
            return self.length == other.length
        else:
            return self.length.cache_key == other.length.cache_key

    def __eq__(self, other):
        if self is other:
            return True

        if type(other) is not SimMemoryObject:
            return NotImplemented

        return self.base == other.base and self._object_equals(other) and self._length_equals(other)

    def __hash__(self):
        obj_hash = hash(self.object) if self.is_bytes else self.object.cache_key
        return hash((obj_hash, self.base, hash(self.length)))

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "MO(%s)" % self.object


class SimLabeledMemoryObject(SimMemoryObject):
    __slots__ = ("label",)

    def __init__(self, obj, base, endness, length=None, byte_width=8, label=None):
        super().__init__(obj, base, endness, length=length, byte_width=byte_width)
        self.label = label


def bv_slice(value: claripy.ast.BV, offset: int, size: int, rev: bool, bw: int) -> claripy.ast.BV:
    """
    Extremely cute utility to pretend you've serialized a value to stored bytes, sliced it a la python slicing, and then
    deserialized those bytes to an integer again.

    :param value:   The bitvector to slice
    :param offset:  The byte offset from the first stored byte to slice from, or a negative offset from the end.
    :param size:    The number of bytes to return. If None, return all bytes from the offset to the end. If larger than
                    the number of bytes from the offset to the end, return all bytes from the offset to the end.
    :param rev:     Whether the pretend-serialization should be little-endian
    :param bw:      The byte width
    :return:        The new bitvector
    """

    vsize = len(value) // bw

    if offset < 0:
        offset = vsize + offset

    if size is None or offset + size > vsize:
        size = vsize - offset
    if rev:
        offset = vsize - (offset + size)

    if offset == 0 and size == vsize:
        return value

    bitstart = len(value) - offset * bw
    if size == 0:
        return claripy.BVV(b"")
    return value[bitstart - 1 : bitstart - size * bw]
