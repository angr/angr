from pyvex.const import get_type_size

from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionData
from ....errors import SimStatementError



def SimIRStmt_LoadG(engine, state, stmt):
    with state.history.subscribe_actions() as addr_deps:
        addr = engine.handle_expression(state, stmt.addr)
    with state.history.subscribe_actions() as alt_deps:
        alt = engine.handle_expression(state, stmt.alt)
    with state.history.subscribe_actions() as guard_deps:
        guard = engine.handle_expression(state, stmt.guard)

    read_type, converted_type = stmt.cvt_types
    read_size_bits = get_type_size(read_type)
    converted_size_bits = get_type_size(converted_type)
    read_size = read_size_bits // state.arch.byte_width

    read_expr = state.memory.load(addr, read_size, endness=stmt.end, condition=guard != 0)
    if read_size_bits == converted_size_bits:
        converted_expr = read_expr
    elif "S" in stmt.cvt:
        converted_expr = read_expr.sign_extend(converted_size_bits - read_size_bits)
    elif "U" in stmt.cvt:
        converted_expr = read_expr.zero_extend(converted_size_bits - read_size_bits)
    else:
        raise SimStatementError("Unrecognized IRLoadGOp %s!" % stmt.cvt)

    read_expr = state.solver.If(guard != 0, converted_expr, alt)

    state.scratch.store_tmp(stmt.dst, read_expr, deps=addr_deps + alt_deps + guard_deps)

    if o.TRACK_MEMORY_ACTIONS in state.options:
        data_ao = SimActionObject(converted_expr)
        alt_ao = SimActionObject(alt, deps=alt_deps, state=state)
        addr_ao = SimActionObject(addr, deps=addr_deps, state=state)
        guard_ao = SimActionObject(guard, deps=guard_deps, state=state)
        size_ao = SimActionObject(converted_size_bits)

        r = SimActionData(state, state.memory.id, SimActionData.READ, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao, fallback=alt_ao)
        state.history.add_action(r)
