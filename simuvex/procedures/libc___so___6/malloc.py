import simuvex
from simuvex.s_type import SimTypeLength, SimTypeTop
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(simuvex.SimProcedure):
    def analyze(self):
        self.argument_types = {0: SimTypeLength(self.state.arch)}

        plugin = self.state.get_plugin('libc')
        sim_size = self.arg(0)

        self.return_type = self.ty_ptr(SimTypeTop(sim_size))

        if self.state.se.symbolic(sim_size):
            size = self.state.se.max_int(sim_size)
            if size > plugin.max_variable_size:
                size = plugin.max_variable_size
        else:
            size = self.state.se.any_int(sim_size) * 8

        addr = plugin.heap_location
        plugin.heap_location += size
        return addr
