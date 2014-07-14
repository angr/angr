import simuvex
from simuvex.s_type import SimTypePointer, SimTypeTop, SimTypeLength

import itertools
import logging
l = logging.getLogger("simuvex.procedures.libc.bcopy")

bcopy_counter = itertools.count()

class bcopy(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        # TODO: some way to say that type(0) == type(1) ?
        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: SimTypeLength(self.state.arch)}
        dst_addr = self.get_arg_expr(0)
        src_addr = self.get_arg_expr(1)
        limit = self.get_arg_expr(2)

        self.exit_return(self.inline_call(simuvex.SimProcedures['libc.so.6']['memcpy'], dst_addr, src_addr, limit))
