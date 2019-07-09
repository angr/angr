def SimIRStmt_WrTmp(engine, state, stmt):
    # get data and track data reads
    with state.history.subscribe_actions() as data_deps:
        data = engine.handle_expression(state, stmt.data)
    state.scratch.store_tmp(stmt.tmp, data, deps=data_deps)

    #actual_size = len(data)
    #expected_size = stmt.data.result_size(state.scratch.tyenv)
    #if actual_size != expected_size:
    #    raise SimStatementError("WrTmp expected length %d but got %d" % (actual_size, expected_size))
