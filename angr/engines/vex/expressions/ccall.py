from pyvex.const import get_type_size

from .... import sim_options as o
from .. import ccall
from ....errors import SimCCallError, UnsupportedCCallError

import logging
l = logging.getLogger(name=__name__)

def SimIRExpr_CCall(engine, state, expr):
    if o.DO_CCALLS not in state.options:
        return state.solver.Unconstrained("ccall_ret", get_type_size(expr.ret_type))

    call_args = [engine.handle_expression(state, e) for e in expr.args]

    if hasattr(ccall, expr.callee.name):
        try:
            func = getattr(ccall, expr.callee.name)
            result, constraints = func(state, *call_args)
            state.solver.add(*constraints)
        except SimCCallError:
            if o.BYPASS_ERRORED_IRCCALL not in state.options:
                raise
            state.history.add_event('resilience', resilience_type='ccall', callee=expr.callee.name, message='ccall raised SimCCallError')
            result = state.solver.Unconstrained("errored_%s" % expr.callee.name, get_type_size(expr.ret_type))
    else:
        l.error("Unsupported CCall %s", expr.callee.name)
        if o.BYPASS_UNSUPPORTED_IRCCALL in state.options:
            if o.UNSUPPORTED_BYPASS_ZERO_DEFAULT in state.options:
                result = state.solver.BVV(0, get_type_size(expr.ret_type))
            else:
                result = state.solver.Unconstrained("unsupported_%s" % expr.callee.name, get_type_size(expr.ret_type))
            state.history.add_event('resilience', resilience_type='ccall', callee=expr.callee.name, message='unsupported ccall')
        else:
            raise UnsupportedCCallError("Unsupported CCall %s" % expr.callee.name)

    return result
