import simuvex
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(simuvex.SimProcedure):
    def __init__(self):
        plugin = self.state.get_plugin('libc')
        sim_size = self.get_arg_value(0)

        if sim_size.is_symbolic():
            size = sim_size.max()
            if size > plugin.max_variable_size:
                size = plugin.max_variable_size
        else:
            size = sim_size.any() * 8

        addr = plugin.heap_location
        plugin.heap_location += size
        self.exit_return(addr)
