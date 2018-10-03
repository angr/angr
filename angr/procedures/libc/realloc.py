import angr
from angr.sim_type import SimTypeLength, SimTypeTop

import logging
l = logging.getLogger("angr.procedures.libc.realloc")

######################################
# realloc
######################################

class realloc(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, ptr, size):
        if size.symbolic:
            try:
                size_int = self.state.solver.max(size, extra_constraints=(size < self.state.libc.max_variable_size,))
            except angr.errors.SimSolverError:
                size_int = self.state.solver.min(size)
            self.state.add_constraints(size_int == size)
        else:
            size_int = self.state.solver.eval(size)

        addr = self.state.libc.heap_location

        if self.state.solver.eval(ptr) != 0:
            v = self.state.memory.load(ptr, size_int)
            self.state.memory.store(addr, v)
            
        self.state.libc.heap_location += size_int

        return addr
