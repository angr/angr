from claripy.fp import FSORT_FLOAT, FSORT_DOUBLE

def size_bits(t):
    '''Returns size, in BITS, of a type.'''
    for s in 256, 128, 64, 32, 16, 8, 1:
        if str(s) in t:
            return s
    raise SimExpressionError("Unable to determine length of %s." % t)

def size_bytes(t):
    '''Returns size, in BYTES, of a type.'''
    s = size_bits(t)
    if s == 1:
        raise SimExpressionError("size_bytes() is seeing a bit!")
    return s/8

def translate_irconst(state, c):
    size = size_bits(c.type)
    if isinstance(c.value, (int, long)):
        return state.se.BVV(c.value, size)
    elif isinstance(c.value, float):
        if size == 32:
            return state.se.FPV(c.value, FSORT_FLOAT)
        elif size == 64:
            return state.se.FPV(c.value, FSORT_DOUBLE)
        else:
            raise SimExpressionError("Unsupported floating point size: %d" % size)
    raise SimExpressionError("Unsupported constant type: %s" % type(c.value))

from .expressions import SimIRExpr, translate_expr
from .statements import SimIRStmt, translate_stmt
from .irsb import SimIRSB, SimIRSBError
from ..s_errors import SimExpressionError
