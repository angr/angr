import logging
l = logging.getLogger(name=__name__)


def SimIRExpr_VECRET(_engine, state, abstract_state, code_loc, _expr):
    l.warning("VECRET IRExpr encountered. This is (probably) not bad, but we have no real idea how to handle it.")
    return state.solver.BVV("unsupported_VECRET", 32)
