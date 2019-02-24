from ..expressions.const import translate_irconst

from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionExit


def SimIRStmt_Exit(engine, state, stmt):
    with state.history.subscribe_actions() as actions:
        guard_int = engine.handle_expression(state, stmt.guard)

    # get the destination
    target = translate_irconst(state, stmt.dst)
    guard = guard_int != 0
    jumpkind = stmt.jumpkind

    if o.TRACK_JMP_ACTIONS in state.options:
        guard_ao = SimActionObject(guard, deps=actions, state=state)
        state.history.add_action(SimActionExit(state, target=target, condition=guard_ao, exit_type=SimActionExit.CONDITIONAL))

    return target, guard, jumpkind
