def size_bits(t):
    '''Returns size, in BITS, of a type.'''
    for s in 256, 128, 64, 32, 16, 8, 1:
        if str(s) in t:
            return s
    raise Exception("Unable to determine length of %s." % t)

def size_bytes(t):
    '''Returns size, in BYTES, of a type.'''
    s = size_bits(t)
    if s == 1:
        raise Exception("size_bytes() is seeing a bit!")
    return s/8

def translate_irconst(state, c):
    size = size_bits(c.type)
    t = type(c.value)
    if t in (int, long):
        return state.se.BitVecVal(c.value, size)
    raise Exception("Unsupported constant type: %s" % type(c.value))

from .expressions import SimIRExpr, translate_expr
from .statements import SimIRStmt, translate_stmt
from .irsb import SimIRSB, SimIRSBError
