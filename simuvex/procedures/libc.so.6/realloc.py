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
                        if size > plugin.max_variable_size:
                                size = plugin.max_variable_size
                else:
                        size = sim_size.any() * 8

                addr = plugin.heap_location
                v = self.state.mem_expr(sim_ptr, size)
                self.state.store_mem(addr, v)
                plugin.heap_location += size

                self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, simuvex.SimValue(addr), 
                                                  simuvex.SimValue(v), size, [], [], [], []))

                self.exit_return(addr)
