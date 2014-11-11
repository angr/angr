import simuvex
from simuvex.s_type import SimTypeLength, SimTypeTop

import logging
l = logging.getLogger("simuvex.procedures.libc.realloc")

######################################
# realloc
######################################

class realloc(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def analyze(self, ptr, size):
        size_int = self.state.se.max_int(size, extra_constraints=
                [self.state.se.ULE(size, self.state.libc.max_variable_size)])
        l.debug("Size: %d", size_int)
        self.state.add_constraints(size_int == size)

        self.argument_types = { 0: self.ty_ptr(SimTypeTop()),
                                1: SimTypeLength(self.state.arch) }
        self.return_type = self.ty_ptr(SimTypeTop(size))

        addr = self.state.libc.heap_location
        v = self.state.mem_expr(ptr, size_int)
        self.state.store_mem(addr, v)
        self.state.libc.heap_location += size_int

        return addr
