import simuvex
from simuvex.s_type import SimTypeLength, SimTypeTop
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(simuvex.SimProcedure):
    def __init__(self): #pylint:disable=W0231
        self.argument_types = {0: SimTypeLength(self.state.arch)}

        plugin = self.state.get_plugin('libc')
        sim_size = self.arg(0)

        self.return_type = self.ty_ptr(SimTypeTop(sim_size))

        if self.state.se.symbolic(sim_size):
            size = self.state.se.max_int(sim_size)
            if size > plugin.max_variable_size:
                size = plugin.max_variable_size
        else:
            size = sim_size.se.any_int() * 8

        addr = plugin.heap_location
        plugin.heap_location += size
        self.ret(addr)
