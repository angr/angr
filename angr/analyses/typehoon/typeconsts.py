"""
All type constants used in type inference. They can be mapped, translated, or rewritten to C-style types.
"""

from typing import Optional


class TypeConstant:

    SIZE = None

    def pp_str(self, mapping) -> str:  # pylint:disable=unused-argument
        return repr(self)

    def __eq__(self, other):
        return type(self) == type(other)

    def __hash__(self):
        return hash(type(self))

    @property
    def size(self) -> int:
        if self.SIZE is None:
            raise NotImplementedError()
        return self.SIZE


class TopType(TypeConstant):

    def __repr__(self):
        return "TOP"


class BottomType(TypeConstant):

    def __repr__(self):
        return "BOT"


class Int(TypeConstant):

    def __repr__(self):
        return "intbase"



class Int1(Int):
    SIZE = 1


class Int8(Int):
    SIZE = 1

    def __repr__(self):
        return "int8"


class Int16(Int):
    SIZE = 2

    def __repr__(self):
        return "int16"


class Int32(Int):
    SIZE = 4

    def __repr__(self):
        return "int32"


class Int64(Int):
    SIZE = 8

    def __repr__(self):
        return "int64"


class Int128(Int):
    SIZE = 16

    def __repr__(self):
        return "int128"


class Pointer(TypeConstant):
    def __init__(self, basetype):
        self.basetype = basetype

    def __eq__(self, other):
        return type(self) is type(other) and self.basetype == other.basetype

    def __hash__(self):
        return hash((type(self), hash(self.basetype)))

    def new(self, basetype):
        return self.__class__(basetype)


class Pointer32(Pointer, Int32):
    """
    32-bit pointers.
    """
    def __init__(self, basetype):
        Pointer.__init__(self, basetype)

    def __repr__(self):
        return "ptr32(%r)" % self.basetype


class Pointer64(Pointer, Int64):
    """
    64-bit pointers.
    """
    def __init__(self, basetype):
        Pointer.__init__(self, basetype)

    def __repr__(self):
        return "ptr64(%r)" % self.basetype


class Array(TypeConstant):
    def __init__(self, element, count=None):
        self.element: TypeConstant = element
        self.count: Optional[int] = count

    def __repr__(self):
        if self.count is None:
            return "%r[?]" % self.element
        else:
            return "%r[%d]" % (self.element, self.count)

    def __eq__(self, other):
        return type(other) is type(self) and self.element == other.element and self.count == other.count

    def __hash__(self):
        return hash((type(self), self.element, self.count))


class Struct(TypeConstant):
    def __init__(self, fields=None):
        self.fields = { } if fields is None else fields  # offset to type

    def _hash_fields(self):
        keys = sorted(self.fields.keys())
        tpl = tuple((k, self.fields[k]) for k in keys)
        return hash(tpl)

    def __repr__(self):
        return "struct%r" % self.fields

    def __eq__(self, other):
        return type(other) is type(self) and self.fields == other.fields

    def __hash__(self):
        return hash((type(self), self._hash_fields()))


class TypeVariableReference(TypeConstant):
    def __init__(self, typevar):
        self.typevar = typevar

    def __repr__(self):
        return "ref(%s)" % self.typevar

    def __eq__(self, other):
        return type(other) is type(self) and self.typevar == other.typevar

    def __hash__(self):
        return hash((type(self), self.typevar))


#
# Methods
#

def int_type(bits):
    mapping = {
        1: Int1,
        8: Int8,
        16: Int16,
        32: Int32,
        64: Int64,
        128: Int128,
    }
    if bits in mapping:
        return mapping[bits]()
    return None
