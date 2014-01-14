import simuvex
import symexec
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(simuvex.SimProcedure):
        def __init__(self):
                plugin = self.state.get_plugin('libc')
                sim_size = simuvex.SimValue(self.get_arg_expr(0))

                if sim_size.is_symbolic():
                        # TODO: find a better way
                        size = sim_size.max() * 8
                        if size > plugin.max_mem_per_variable:
                                size = plugin.max_mem_per_variable
                else:
                        size = sim_size.any() * 8

                addr = plugin.heap_location
                self.state.get_plugin('libc').heap_location += size
                mem_id = "%s_%x_%d" % (plugin.heap_id, addr, malloc_mem_counter.next())
                v = symexec.BitVec(mem_id, size)
                self.state.store_mem(addr, v)

                # TODO: SimMemRef
                # ask idx???

                self.exit_return(addr)
