from pyvex.const import get_type_size

from .... import sim_options as o
from ....state_plugins.sim_action import SimActionData


def SimIRExpr_GetI(engine, state, expr):
    ix = engine.handle_expression(state, expr.ix)
    size_in_bits = get_type_size(expr.descr.elemTy)
    size = size_in_bits // state.arch.byte_width

    array_base = expr.descr.base
    array_index = (ix + expr.bias) % expr.descr.nElems
    offset = array_base + array_index*size

    # get it!
    result = state.registers.load(offset, size)

    if expr.descr.elemTy.startswith('Ity_F'):
        result = result.raw_to_fp()

    # finish it and save the register references
    if o.TRACK_REGISTER_ACTIONS in state.options:
        r = SimActionData(state, state.registers.id, SimActionData.READ, addr=offset, size=size_in_bits, data=result)
        state.history.add_action(r)

    return result
