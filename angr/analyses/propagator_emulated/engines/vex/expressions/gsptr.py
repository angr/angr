def SimIRExpr_GSPTR(_engine, state, _expr):
    return state.solver.BVV(0, state.arch.bits)
