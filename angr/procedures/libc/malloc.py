import angr
from angr.sim_type import SimTypeLength, SimTypeTop
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sim_size):
        self.argument_types = {0: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop(sim_size))

        if self.state.solver.symbolic(sim_size):
            size = self.state.solver.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.solver.eval(sim_size)

        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size
        return addr
