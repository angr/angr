import simuvex
from simuvex.s_type import SimTypeLength, SimTypeTop

import logging
l = logging.getLogger("simuvex.procedures.libc.realloc")

######################################
# realloc
######################################

class realloc(simuvex.SimProcedure):
    def analyze(self):
        plugin = self.state.get_plugin('libc')
        ptr = self.arg(0)
        size = self.arg(1)

        size_int = self.state.se.max_int(size, extra_constraints=
                [self.state.se.ULE(size, plugin.max_variable_size)])
        l.debug("Size: %d", size_int)
        self.state.add_constraints(size_int == size)

        self.argument_types = { 0: self.ty_ptr(SimTypeTop()),
                                1: SimTypeLength(self.state.arch) }
        self.return_type = self.ty_ptr(SimTypeTop(size))

        addr = plugin.heap_location
        v = self.state.mem_expr(ptr, size_int)
        self.state.store_mem(addr, v)
        plugin.heap_location += size_int

        return addr
