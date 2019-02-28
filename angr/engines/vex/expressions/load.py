from pyvex.const import get_type_size

from .... import sim_options as o
from ....state_plugins.sim_action import SimActionData
from ....state_plugins.sim_action_object import SimActionObject
from ....errors import SimUninitializedAccessError


def SimIRExpr_Load(engine, state, expr):
    # size of the load
    size_bits = get_type_size(expr.type)
    size = size_bits // state.arch.byte_width

    # get the address expression and track stuff
    with state.history.subscribe_actions() as addr_actions:
        addr = engine.handle_expression(state, expr.addr)

    if o.UNINITIALIZED_ACCESS_AWARENESS in state.options:
        if getattr(addr._model_vsa, 'uninitialized', False):
            raise SimUninitializedAccessError('addr', addr)

    if o.DO_LOADS not in state.options:
        # only do the load if, uh, we have to
        result = state.solver.Unconstrained("load_expr_%#x_%d" % (state.scratch.ins_addr, state.scratch.stmt_idx), size_bits)
    else:
        # load from memory and fix endianness
        result = state.memory.load(addr, size, endness=expr.endness)

    if expr.type.startswith('Ity_F'):
        result = result.raw_to_fp()

    # finish it and save the mem read

    if o.TRACK_MEMORY_ACTIONS in state.options:
        addr_ao = SimActionObject(addr, deps=addr_actions, state=state)
        r = SimActionData(state, state.memory.id, SimActionData.READ, addr=addr_ao, size=size_bits, data=result)
        state.history.add_action(r)

    return result
