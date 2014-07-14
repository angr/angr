import simuvex
from simuvex.s_type import SimTypeLength, SimTypePointer, SimTypeTop
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(simuvex.SimProcedure):
    def __init__(self):
        self.argument_types = {0: SimTypeLength()}

        plugin = self.state.get_plugin('libc')
        sim_size = self.get_arg_value(0)

        self.return_type = self.ty_ptr(SimTypeTop(sim_size))

        if sim_size.is_symbolic():
            size = sim_size.max()
            if size > plugin.max_variable_size:
                size = plugin.max_variable_size
        else:
            size = sim_size.any() * 8

        addr = plugin.heap_location
        plugin.heap_location += size
        self.exit_return(addr)
