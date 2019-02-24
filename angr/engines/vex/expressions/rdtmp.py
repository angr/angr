from .... import sim_options as o
from ....state_plugins.sim_action import SimActionData


def SimIRExpr_RdTmp(_, state, expr):
    if o.SUPER_FASTPATH in state.options and expr.tmp >= len(state.scratch.temps):
        result = state.solver.BVV(0, state.scratch.tyenv.sizeof(expr.tmp))
    else:
        result = state.scratch.tmp_expr(expr.tmp)

    # finish it and save the tmp reference
    if o.TRACK_TMP_ACTIONS in state.options:
        r = SimActionData(state, SimActionData.TMP, SimActionData.READ, tmp=expr.tmp, size=state.scratch.tyenv.sizeof(expr.tmp), data=result)
        state.history.add_action(r)

    return result
