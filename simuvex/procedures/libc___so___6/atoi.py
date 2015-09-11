import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.libc.strlen")

class atoi(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch, True)

        atoi_in = simuvex.SimProcedures['libc.so.6']['__atoi_inner']
        return self.inline_call(atoi_in, s, self.state.memory).ret_expr
