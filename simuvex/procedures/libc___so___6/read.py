import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength, SimTypePointer

######################################
# read
######################################

class read(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231
        # TODO: Symbolic fd
        fd = self.get_arg_value(0)
        sim_dst = self.get_arg_value(1)
        sim_length = self.get_arg_value(2)

        self.argument_types = {0: SimTypeFd(),
                               1: self.ty_ptr(SimTypeArray(SimTypeChar(), sim_length.expr)),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeLength(self.state.arch)
        plugin = self.state['posix']

        if sim_length.is_symbolic():
            # TODO improve this
            length = min(sim_length.max(), plugin.max_length)
        else:
            length = sim_length.any()

        # TODO handle errors
        data = plugin.read(fd.expr, length)
        self.state.store_mem(sim_dst.expr, data)
        self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, sim_dst, self.state.expr_value(data), length, [], [], [], []))

        self.exit_return(sim_length.expr)
