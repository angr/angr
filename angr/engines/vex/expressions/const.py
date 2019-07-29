from pyvex.const import get_type_size
from claripy.fp import FSORT_FLOAT, FSORT_DOUBLE

from .... import sim_options as o
from ....errors import UnsupportedIRExprError, SimExpressionError

def SimIRExpr_Const(_, state, expr):
    return translate_irconst(state, expr.con)

def translate_irconst(state, c):
    size = get_type_size(c.type)
    if isinstance(c.value, int):
        return state.solver.BVV(c.value, size)
    elif isinstance(c.value, float):
        if o.SUPPORT_FLOATING_POINT not in state.options:
            raise UnsupportedIRExprError("floating point support disabled")
        if size == 32:
            return state.solver.FPV(c.value, FSORT_FLOAT)
        elif size == 64:
            return state.solver.FPV(c.value, FSORT_DOUBLE)
        else:
            raise SimExpressionError("Unsupported floating point size: %d" % size)
    raise SimExpressionError("Unsupported constant type: %s" % type(c.value))

