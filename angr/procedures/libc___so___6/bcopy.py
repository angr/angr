import simuvex
from simuvex.s_type import SimTypeTop, SimTypeLength

import itertools
import logging
l = logging.getLogger("simuvex.procedures.libc.bcopy")

bcopy_counter = itertools.count()

class bcopy(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):
        # TODO: some way to say that type(0) == type(1) ?
        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: SimTypeLength(self.state.arch)}

        return self.inline_call(simuvex.SimProcedures['libc.so.6']['memcpy'], dst_addr, src_addr, limit).ret_expr
