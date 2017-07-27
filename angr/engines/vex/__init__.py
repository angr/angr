from claripy.fp import FSORT_FLOAT, FSORT_DOUBLE
from ...errors import SimExpressionError, UnsupportedIRExprError

def size_bits(t):
    """Returns size, in BITS, of a type."""
    assert t.startswith("Ity_")
    if "INVALID" in t:
        raise SimExpressionError("Ity_INVALID passed to size_bits")
    return int(t[5:])

def size_bytes(t):
    """Returns size, in BYTES, of a type."""
    s = size_bits(t)
    if s == 1:
        raise SimExpressionError("size_bytes() is seeing a bit!")
    return s/8

def translate_irconst(state, c):
    size = size_bits(c.type)
    if isinstance(c.value, (int, long)):
        return state.se.BVV(c.value, size)
    elif isinstance(c.value, float):
        if options.SUPPORT_FLOATING_POINT not in state.options:
            raise UnsupportedIRExprError("floating point support disabled")
        if size == 32:
            return state.se.FPV(c.value, FSORT_FLOAT)
        elif size == 64:
            return state.se.FPV(c.value, FSORT_DOUBLE)
        else:
            raise SimExpressionError("Unsupported floating point size: %d" % size)
    raise SimExpressionError("Unsupported constant type: %s" % type(c.value))

from .expressions import SimIRExpr, translate_expr
from .statements import SimIRStmt, translate_stmt
from .engine import SimEngineVEX
from . import ccall

from .irop import operations

from ... import sim_options as options
