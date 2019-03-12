from pyvex import get_type_size

import logging
l = logging.getLogger(name=__name__)

# TODO: memory read SimActions
# TODO: tmp write SimActions

def SimIRStmt_LLSC(engine, state, stmt):
    #l.warning("LLSC is handled soundly but imprecisely.")
    with state.history.subscribe_actions() as addr_actions:
        addr = engine.handle_expression(state, stmt.addr)

    if stmt.storedata is None:
        # it's a load-linked
        load_size = get_type_size(state.scratch.tyenv.lookup(stmt.result))//state.arch.byte_width
        data = state.memory.load(addr, load_size, endness=stmt.endness)
        state.scratch.store_tmp(stmt.result, data, deps=addr_actions)
    else:
        # it's a store-conditional
        #result = state.solver.Unconstrained('llcd_result', 1)

        #new_data = self._translate_expr(stmt.storedata)
        #old_data = state.memory.load(addr, new_data.size_bytes(), endness=stmt.endness)

        #store_data = state.solver.If(result == 1, new_data, old_data)

        # for single-threaded programs, an SC will never fail. For now, we just assume it succeeded.
        with state.history.subscribe_actions() as data_actions:
            store_data = engine.handle_expression(state, stmt.storedata)

        # the action
        if o.TRACK_MEMORY_ACTIONS in state.options:
            data_ao = SimActionObject(store_data, deps=data_actions, state=state)
            addr_ao = SimActionObject(addr, deps=addr_actions, state=state)
            #guard_ao = SimActionObject(result == 1))
            size_ao = SimActionObject(len(store_data))
            a = SimActionData(state, state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, size=size_ao)
            state.history.add_action(a)
        else:
            a = None

        state.memory.store(addr, store_data, action=a)
        result = state.solver.BVV(1, 1)
        state.scratch.store_tmp(stmt.result, result, deps=addr_actions + data_actions)

from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionData
from .... import sim_options as o
