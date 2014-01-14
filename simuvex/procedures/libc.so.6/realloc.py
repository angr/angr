import simuvex
import symexec

######################################
# realloc
######################################

class realloc(simuvex.SimProcedure):
        def __init__(self):
                plugin = self.state.get_plugin('libc')
                sim_ptr = self.get_arg_value(0)
                sim_size = self.get_arg_value(1)

                if sim_size.is_symbolic():
                        # TODO: find a better way
                        size = sim_size.max() * 8
                        if size > plugin.max_mem_per_variable:
                                size = plugin.max_mem_per_variable
                else:
                        size = sim_size.any() * 8

                addr = plugin.heap_location
                self.state.store_mem(addr, self.state.mem_expr(sim_ptr, size))
                plugin.heap_location += size

                # TODO: do the refs
                self.exit_return(addr)
