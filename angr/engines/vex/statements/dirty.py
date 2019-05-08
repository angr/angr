from .. import dirty
from ....errors import UnsupportedDirtyError

import logging
l = logging.getLogger(name=__name__)

def SimIRStmt_Dirty(engine, state, stmt):
    # Example:
    # t1 = DIRTY 1:I1 ::: ppcg_dirtyhelper_MFTB{0x7fad2549ef00}()
    with state.history.subscribe_actions() as deps:
        exprs = [engine.handle_expression(state, e) for e in stmt.args]

    func = state.trace_replay_overrides.override_for_dirtyhelper(stmt.cee.name)
    if func is None:
        func = getattr(dirty, stmt.cee.name, None)

    if func is not None:
        retval, retval_constraints = func(state, *exprs)
        state.solver.add(*retval_constraints)

        if stmt.tmp not in (0xffffffff, -1):
            state.scratch.store_tmp(stmt.tmp, retval, deps=deps)
    else:
        l.error("Unsupported dirty helper %s", stmt.cee.name)
        raise UnsupportedDirtyError("Unsupported dirty helper %s" % stmt.cee.name)
