# TODO: mem read SimActions

def SimIRStmt_CAS(engine, state, stmt):
    # first, get the expression of the add
    with state.history.subscribe_actions() as addr_actions:
        addr = engine.handle_expression(state, stmt.addr)

    # figure out if it's a single or double
    double_element = (stmt.oldHi != 0xFFFFFFFF) and (stmt.expdHi is not None)

    if double_element:
        # translate the expected values
        with state.history.subscribe_actions() as cond_actions:
            expd_lo = engine.handle_expression(state, stmt.expdLo)
            expd_hi = engine.handle_expression(state, stmt.expdHi)

        # read the old values
        old_cnt = state.memory.load(addr, len(expd_lo)*2//8, endness=stmt.endness)
        old_hi, old_lo = old_cnt.chop(bits=len(expd_lo))
        state.scratch.store_tmp(stmt.oldLo, old_lo, None, None)
        state.scratch.store_tmp(stmt.oldHi, old_hi, None, None)

        # the write data
        with state.history.subscribe_actions() as data_actions:
            data_lo = engine.handle_expression(state, stmt.dataLo)
            data_hi = engine.handle_expression(state, stmt.dataHi)
        data = state.solver.Concat(data_hi, data_lo)

        # do it
        condition = state.solver.And(old_lo == expd_lo, old_hi == expd_hi)
        data_ao = SimActionObject(data, deps=data_actions, state=state)
        addr_ao = SimActionObject(addr, deps=addr_actions, state=state)
        guard_ao = SimActionObject(condition, deps=cond_actions, state=state)
        size_ao = SimActionObject(len(data))

        a = SimActionData(state, state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao)
        state.memory.store(addr, data, condition=condition, endness=stmt.endness, action=a)
        state.history.add_action(a)
    else:
        # translate the expected value
        with state.history.subscribe_actions() as cond_actions:
            expd_lo = engine.handle_expression(state, stmt.expdLo)

        # read the old values
        old_lo = state.memory.load(addr, len(expd_lo)//state.arch.byte_width, endness=stmt.endness)
        state.scratch.store_tmp(stmt.oldLo, old_lo, None, None)

        # the write data
        with state.history.subscribe_actions() as data_actions:
            data = engine.handle_expression(state, stmt.dataLo)

        # do it
        condition = old_lo == expd_lo

        data_ao = SimActionObject(data, deps=data_actions, state=state)
        addr_ao = SimActionObject(addr, deps=addr_actions, state=state)
        guard_ao = SimActionObject(condition, deps=cond_actions, state=state)
        size_ao = SimActionObject(len(data))

        a = SimActionData(state, state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao)
        state.memory.store(addr, data, condition=condition, endness=stmt.endness, action=a)

from ....state_plugins.sim_action import SimActionData
from ....state_plugins.sim_action_object import SimActionObject
