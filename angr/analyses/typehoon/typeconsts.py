
"""
All type constants used in type inference. They can be mapped, translated, or rewritten to C-style types.
"""


class TypeConstant:
    pass


class TopType(TypeConstant):
    pass


class BottomType(TypeConstant):
    pass


class Char(TypeConstant):
    pass


class Int1(TypeConstant):
    pass


class Int8(TypeConstant):
    pass


class Int16(TypeConstant):
    pass


class Int32(TypeConstant):

    def __repr__(self):
        return "int32"


class Int64(TypeConstant):

    def __repr__(self):
        return "int64"


class Int128(TypeConstant):

    def __repr__(self):
        return "int128"


class Pointer(TypeConstant):
    def __init__(self, basetype):
        self.basetype = basetype


class Pointer32(Pointer, Int32):
    """
    32-bit pointers.
    """
    def __init__(self, basetype):
        Pointer.__init__(self, basetype)


class Pointer64(Pointer, Int64):
    """
    64-bit pointers.
    """
    def __init__(self, basetype):
        Pointer.__init__(self, basetype)


#
# Methods
#

def int_type(bits):
    map = {
        1: Int1,
        8: Int8,
        16: Int16,
        32: Int32,
        64: Int64,
        128: Int128,
    }
    return map[bits]()
