import simuvex
from simuvex.s_type import SimTypeTop, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.memcpy")

class memcpy(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):
        # TODO: look into smarter types here
        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop())

        if not self.state.se.symbolic(limit):
            conditional_size = self.state.se.any_int(limit)
        else:
            max_memcpy_size = self.state['libc'].max_buffer_size
            conditional_size = max(self.state.se.min_int(limit), min(self.state.se.max_int(limit), max_memcpy_size))

        l.debug("Memcpy running with conditional_size %d", conditional_size)

        if conditional_size > 0:
            src_mem = self.state.mem_expr(src_addr, conditional_size, endness='Iend_BE')
            self.state.store_mem(dst_addr, src_mem, size=limit, endness='Iend_BE')


        return dst_addr
