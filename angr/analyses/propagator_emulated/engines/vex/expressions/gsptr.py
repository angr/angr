def SimIRExpr_GSPTR(_engine, state, abstract_state, code_loc, _expr):
    return state.solver.BVV(0, state.arch.bits)
