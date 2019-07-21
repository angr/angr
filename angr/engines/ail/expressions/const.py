from claripy.fp import FSORT_FLOAT, FSORT_DOUBLE

from .... import sim_options as o
from ....errors import UnsupportedIRExprError, SimExpressionError

# Mostly identical to VEX const IR expression handler
def SimIRExpr_Const(_, state, expr):
    return translate_irconst(state, expr.con)

def translate_irconst(state, c):
    if isinstance(c.value, int):
        return state.solver.BVV(c.value, c.size)
    elif isinstance(c.value, float):
        if o.SUPPORT_FLOATING_POINT not in state.options:
            raise UnsupportedIRExprError("floating point support disabled")
        if c.size == 32:
            return state.solver.FPV(c.value, FSORT_FLOAT)
        elif c.size == 64:
            return state.solver.FPV(c.value, FSORT_DOUBLE)
        else:
            raise SimExpressionError("Unsupported floating point size: %d" % c.size)
    raise SimExpressionError("Unsupported constant type: %s" % type(c.value))
