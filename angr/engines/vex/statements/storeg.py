from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionData


def SimIRStmt_StoreG(engine, state, stmt):
    with state.history.subscribe_actions() as addr_deps:
        addr = engine.handle_expression(state, stmt.addr)
    with state.history.subscribe_actions() as data_deps:
        data = engine.handle_expression(state, stmt.data)
    expr = data.raw_to_bv()
    with state.history.subscribe_actions() as guard_deps:
        guard = engine.handle_expression(state, stmt.guard)

    if o.TRACK_MEMORY_ACTIONS in state.options:
        data_ao = SimActionObject(expr, deps=data_deps, state=state)
        addr_ao = SimActionObject(addr, deps=addr_deps, state=state)
        guard_ao = SimActionObject(guard, deps=guard_deps, state=state)
        size_ao = SimActionObject(len(expr))

        a = SimActionData(state, state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao)
        state.history.add_action(a)
    else:
        a = None

    state.memory.store(addr, expr, condition=guard == 1, endness=stmt.end, action=a)
