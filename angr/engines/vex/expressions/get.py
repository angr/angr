from pyvex.const import get_type_size

from .... import sim_options as o
from ....state_plugins.sim_action import SimActionData


def SimIRExpr_Get(_, state, expr):
    size_in_bits = get_type_size(expr.ty)
    size = size_in_bits // state.arch.byte_width

    # get it!
    result = state.registers.load(expr.offset, size)

    if expr.type.startswith('Ity_F'):
        result = result.raw_to_fp()

    # finish it and save the register references
    if o.TRACK_REGISTER_ACTIONS in state.options:
        r = SimActionData(state, state.registers.id, SimActionData.READ, addr=expr.offset,
                          size=size_in_bits, data=result
                          )
        state.history.add_action(r)

    return result
