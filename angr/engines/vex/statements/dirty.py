from .. import dirty
from ....errors import UnsupportedDirtyError

import logging
l = logging.getLogger(name=__name__)

def SimIRStmt_Dirty(engine, state, stmt):
    # Example:
    # t1 = DIRTY 1:I1 ::: ppcg_dirtyhelper_MFTB{0x7fad2549ef00}()
    with state.history.subscribe_actions() as deps:
        exprs = [engine.handle_expression(state, e) for e in stmt.args]

    # get the function
    func = getattr(dirty, stmt.cee.name, None)

    # trigger the inspect
    state._inspect('dirty', when=BP_BEFORE, dirty_name=stmt.cee.name, dirty_args=exprs, dirty_handler=func, dirty_result=NO_OVERRIDE)
    retval = state._inspect_getattr('dirty_result', NO_OVERRIDE)
    func = state._inspect_getattr('dirty_handler', func)
    exprs = state._inspect_getattr('dirty_args', exprs)

    if func is None and retval is NO_OVERRIDE:
        l.error("Unsupported dirty helper %s", stmt.cee.name)
        raise UnsupportedDirtyError("Unsupported dirty helper %s" % stmt.cee.name)

    if retval is NO_OVERRIDE:
        retval, retval_constraints = func(state, *exprs)
        state.solver.add(*retval_constraints)

    state._inspect('dirty', when=BP_AFTER, dirty_result=retval)
    if retval is not None and stmt.tmp not in (0xffffffff, -1):
        state.scratch.store_tmp(stmt.tmp, retval, deps=deps)

from ....state_plugins.inspect import BP_BEFORE, BP_AFTER, NO_OVERRIDE
