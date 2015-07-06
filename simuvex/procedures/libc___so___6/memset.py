import simuvex
from simuvex.s_type import SimTypeTop, SimTypeInt, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.memset")

######################################
# memset
######################################

class memset(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, char, num):
        char = char[7:0]

        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                       1: SimTypeInt(32, True), # ?
                       2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop())

        if self.state.se.symbolic(num):
            l.debug("symbolic length")
            max_size = self.state.se.min_int(num) + self.state.libc.max_buffer_size
            write_bytes = self.state.se.Concat(*([ char ] * max_size))
            self.state.memory.store(dst_addr, write_bytes, size=num)
        else:
            max_size = self.state.se.any_int(num)
            if max_size == 0:
                self.ret(dst_addr)
                return

            write_bytes = self.state.se.Concat(*([ char ] * max_size))
            self.state.memory.store(dst_addr, write_bytes)

            l.debug("memset writing %d bytes", max_size)

        return dst_addr
