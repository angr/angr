import simuvex
from simuvex.s_type import SimTypeTop, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.memmove")

class memmove(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        # TODO: look into smarter types here
        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop())

        memcpy = simuvex.SimProcedures['libc.so.6']['memcpy']

        dst_addr = self.arg(0)
        src_addr = self.arg(1)
        limit = self.arg(2)
        self.inline_call(memcpy, dst_addr, src_addr, limit)
        self.ret(dst_addr)
