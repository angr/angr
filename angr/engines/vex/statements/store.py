from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionData


def SimIRStmt_Store(engine, state, stmt):
    # first resolve the address and record stuff
    with state.history.subscribe_actions() as addr_deps:
        addr = engine.handle_expression(state, stmt.addr)

    # now get the value and track everything
    with state.history.subscribe_actions() as data_deps:
        data = engine.handle_expression(state, stmt.data)
    expr = data.raw_to_bv()

    # track the write
    if o.TRACK_MEMORY_ACTIONS in state.options:
        data_ao = SimActionObject(expr, deps=data_deps, state=state)
        addr_ao = SimActionObject(addr, deps=addr_deps, state=state)
        size_ao = SimActionObject(len(data))
        a = SimActionData(state, SimActionData.MEM, SimActionData.WRITE, data=data_ao, size=size_ao, addr=addr_ao)
        state.history.add_action(a)
    else:
        a = None


    # Now do the store (if we should)
    if o.DO_STORES in state.options:
        state.memory.store(addr, data, action=a, endness=stmt.endness)
