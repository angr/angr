import angr
from angr.sim_type import SimTypeTop, SimTypeLength

import logging
l = logging.getLogger("angr.procedures.libc___so___6.memmove")

class memmove(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):
        # TODO: look into smarter types here
        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop())

        memcpy = angr.SIM_PROCEDURES['libc.so.6']['memcpy']

        self.inline_call(memcpy, dst_addr, src_addr, limit)
        return dst_addr
