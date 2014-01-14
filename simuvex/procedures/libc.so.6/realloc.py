import simuvex
import symexec
import itertools
######################################
# malloc
######################################

malloc_mem_counter = itertools.count()
heap_id = 'heap'
max_mem_allocable_per_variable = 2 ** 16

class realloc(simuvex.SimProcedure):
    def __init__(self):
        # TODO add convention
        simuvex.SimProcedure.__init__(self)

        if isinstance(self.state.arch, simuvex.SimAMD64):
            sim_ptr = simuvex.SimValue(self.get_arg_expr(0))
            sim_size = simuvex.SimValue(self.get_arg_expr(1))

            if sim_size.is_symbolic():
                # TODO: find a better way
                size = sim_size.max() * 8
                if size > max_mem_allocable_per_variable:
                    size = max_mem_allocable_per_variable
            else:
                size = sim_size.any() * 8

            addr = self.state.get_plugin('libc').heap_location
            self.state.store_mem(addr, self.state.mem_expr(sim_ptr, size))
            self.state.get_plugin('libc').heap_location += size

            # TODO: do the refs
            self.exit_return(addr)
