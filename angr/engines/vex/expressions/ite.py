def SimIRExpr_ITE(engine, state, expr):
    cond = engine.handle_expression(state, expr.cond)
    expr0 = engine.handle_expression(state, expr.iffalse)
    exprX = engine.handle_expression(state, expr.iftrue)

    return state.solver.If(cond == 0, expr0, exprX)
