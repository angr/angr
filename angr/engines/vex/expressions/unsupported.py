import logging
l = logging.getLogger(name=__name__)


def SimIRExpr_Unsupported(_engine, state, expr):
    l.error("Unsupported IRExpr %s. Please implement.", type(expr).__name__)
    size = expr.result_size(state.scratch.tyenv)
    result = state.solver.Unconstrained(type(expr).__name__, size)
    state.history.add_event('resilience', resilience_type='irexpr', expr=type(expr).__name__, message='unsupported irexpr')
    return result
