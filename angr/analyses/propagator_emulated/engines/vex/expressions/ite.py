def SimIRExpr_ITE(engine, state, abstract_state, code_loc, expr):
    cond = engine.handle_expression(state, abstract_state, code_loc, expr.cond)
    expr0 = engine.handle_expression(state, abstract_state, code_loc, expr.iffalse)
    exprX = engine.handle_expression(state, abstract_state, code_loc, expr.iftrue)

    return state.solver.If(cond == 0, expr0, exprX)
